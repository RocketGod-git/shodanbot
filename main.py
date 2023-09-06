import json
import logging
import discord
from discord import Embed
import shodan

# Reset logging configuration to clear any handlers
logging.root.handlers = []

# Define the logger and handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler with a specific level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# Create formatter and add it to the handler
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] - %(message)s')
ch.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(ch)

# Mute the discord library's logs
logging.getLogger('discord').setLevel(logging.CRITICAL)
def load_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def check_configurations(config):
    if not config:
        return False

    required_keys = ['TOKEN', 'SHODAN_KEY']
    missing_keys = [key for key in required_keys if key not in config]

    if missing_keys:
        logger.error(f"Missing keys in config.json: {', '.join(missing_keys)}")
        return False

    return True

class aclient(discord.Client):
    def __init__(self, shodan_key) -> None:
        super().__init__(intents=discord.Intents.default())
        self.shodan = shodan.Shodan(shodan_key)
        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="the world")
        self.discord_message_limit = 2000

    async def send_split_messages(self, interaction, message: str, require_response=True):
        """Sends a message, and if it's too long for Discord, splits it."""
        # Handle empty messages
        if not message.strip():
            logger.warning("Attempted to send an empty message.")
            return

        # Extract the user's query/command from the interaction to prepend it to the first chunk
        query = ""
        for option in interaction.data.get("options", []):
            if option.get("name") == "query":
                query = option.get("value", "")
                break

        prepend_text = ""
        if query:
            prepend_text = f"Query: {query}\n\n"
                        
        # Add prepend_text to the message
        message = prepend_text + message

        lines = message.split("\n")
        chunks = []
        current_chunk = ""

        for line in lines:
            # If adding the next line to the current chunk would exceed the Discord message limit
            if len(current_chunk) + len(line) + 1 > self.discord_message_limit:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        if current_chunk:
            chunks.append(current_chunk)

        # Check if there are chunks to send
        if not chunks:
            logger.warning("No chunks generated from the message.")
            return

        # If a response is required and the interaction hasn't been responded to, defer the response
        if require_response and not interaction.response.is_done():
            await interaction.response.defer(ephemeral=False)

        # Edit the deferred response
        try:
            await interaction.followup.send(content=chunks[0], ephemeral=False)
            chunks = chunks[1:]  # Remove the first chunk since we've already sent it
        except Exception as e:
            logger.error(f"Failed to send the first chunk via followup. Error: {e}")

        # Send the rest of the chunks directly to the channel
        for chunk in chunks:
            try:
                await interaction.channel.send(chunk)
            except Exception as e:
                logger.error(f"Failed to send a message chunk to the channel. Error: {e}")

async def handle_errors(interaction, error, error_type="Error"):
    error_message = f"{error_type}: {error}"
    try:
        # Check if the interaction has been responded to
        if interaction.response.is_done():
            await interaction.followup.send(error_message)
        else:
            await interaction.response.send_message(error_message, ephemeral=True)
    except discord.HTTPException as http_err:
        logger.warning(f"HTTP error while responding to {interaction.user}: {http_err}")
        try:
            await interaction.followup.send(error_message)
        except discord.HTTPException as followup_http_err:
            logger.error(f"HTTP error during followup to {interaction.user}: {followup_http_err}")
        except Exception as unexpected_followup_error:
            logger.error(f"Unexpected error during followup to {interaction.user}: {unexpected_followup_error}")
    except Exception as unexpected_err:
        logger.error(f"Unexpected error while responding to {interaction.user}: {unexpected_err}")
        try:
            await interaction.followup.send("An unexpected error occurred. Please try again later.")
        except Exception as followup_error:
            logger.error(f"Failed to send followup: {followup_error}")

def run_discord_bot(token, shodan_key):
    client = aclient(shodan_key)

    @client.event
    async def on_ready():
        await client.tree.sync()
        logger.info(f'{client.user} is done sleeping. Lets go!')
        await client.change_presence(activity=client.activity)

    @client.tree.command(name="hostinfo", description="Get information about a host.")
    async def hostinfo(interaction: discord.Interaction, host_ip: str):
        try:
            host_info = client.shodan.host(host_ip)
            await client.send_split_messages(interaction, f"IP: {host_info['ip_str']}\nOS: {host_info.get('os', 'Unknown')}")
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="protocols", description="List supported protocols.")
    async def protocols(interaction: discord.Interaction):
        try:
            protocol_list = client.shodan.protocols()
            formatted_protocols = "\n".join([f"- {protocol}" for protocol in protocol_list])

            await client.send_split_messages(interaction, formatted_protocols)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(
        name="search",
        description="Advanced and basic Shodan queries. Use `/help search` for examples."
    )
    async def search(interaction: discord.Interaction, query: str, max_results: int = 10, display_mode: str = "full"):
        """
        :param query: The Shodan query.
        :param max_results: The maximum number of results to display. Defaults to 10.
        :param display_mode: Either "full" for full details or "easy" for list of IP:ports. Defaults to "full".
        """
        await interaction.response.defer(ephemeral=False)
        
        try:
            query = query.strip()  
            result = client.shodan.search(query)
            await process_shodan_results(interaction, result, max_results, display_mode)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchcity", description="Search Shodan by city.")
    async def searchcity(interaction: discord.Interaction, city: str):
        city = city.strip()
        
        try:
            result = client.shodan.search(f"city:\"{city}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchorg", description="Search Shodan by organization.")
    async def searchorg(interaction: discord.Interaction, organization: str):
        try:
            await interaction.response.defer(ephemeral=False)
            result = client.shodan.search(f"org:\"{organization}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchport", description="Search Shodan by port.")
    async def searchport(interaction: discord.Interaction, port: int):
        try:
            await interaction.response.defer(ephemeral=False)
            result = client.shodan.search(f"port:{port}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchcountry", description="Search Shodan by country using a 2-letter country code (e.g., 'US' for the United States).")
    async def searchcountry(interaction: discord.Interaction, country_code: str):
        try:
            # Convert country code to uppercase to ensure case-insensitivity
            country_code = country_code.upper()

            # Ensure the country code is valid
            if len(country_code) != 2:
                await interaction.response.send_message("Please provide a valid 2-letter country code (e.g., 'US' for the United States).", ephemeral=True)
                return

            result = client.shodan.search(f"country:\"{country_code}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
    
    @client.tree.command(name="exploitsearch", description="Search for known vulnerabilities using a term.")
    async def exploitsearch(interaction: discord.Interaction, term: str):
        try:
            exploit_search = client.shodan.exploits.search(term)
            
            if 'matches' in exploit_search and exploit_search['matches']:
                top_exploits = exploit_search['matches'][:10]
                replies = []
                
                for exploit in top_exploits:
                    description = exploit.get('description', 'No description available.').strip()
                    source = exploit.get('source', 'Unknown source')
                    date = exploit.get('date', 'Unknown date')
                    exploit_type = exploit.get('type', 'Unknown type')
                    
                    detailed_info = (f"**Description:** {description}\n"
                                    f"**Source:** {source}\n"
                                    f"**Date:** {date}\n"
                                    f"**Type:** {exploit_type}\n"
                                    f"---")
                    replies.append(detailed_info)

                message = "\n".join(replies)
                await client.send_split_messages(interaction, message)
            else:
                await interaction.followup.send("No exploits found for that term.")
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(
        name="listtags", 
        description="Get Shodan Exploits tags. Specify size (1-100). E.g., `/listtags 5`."
    )
    async def listtags(interaction: discord.Interaction, size: int = 10):
        """
        Retrieves a list of popular exploit tags from Shodan based on a specified size.
        """
        try:
            if not 1 <= size <= 100:
                await interaction.response.send_message(
                    "The provided size is out of bounds. Please specify a value between 1 and 100.",
                    ephemeral=True
                )
                return

            tags = client.shodan.exploits.tags(size=size)
            tag_list = ", ".join([tag['value'] for tag in tags['matches']])
            
            # Improved message formatting for clarity
            if not tag_list:
                message = "No popular exploit tags found."
            elif size == 1:
                message = f"The most popular exploit tag is: {tag_list}"
            else:
                message = f"Here are the top {size} popular exploit tags: {tag_list}"

            await interaction.followup.send(message)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchnetblock", description="Search devices in a specific netblock.")
    async def searchnetblock(interaction: discord.Interaction, netblock: str):
        try:
            result = client.shodan.search(f"net:{netblock}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
                       
    @client.tree.command(name="searchproduct", description="Search devices associated with a specific product.")
    async def searchproduct(interaction: discord.Interaction, product: str):
        try:
            result = client.shodan.search(f"product:{product}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchssl", description="Search for domains associated with a specific SSL certificate hash.")
    async def searchssl(interaction: discord.Interaction, ssl_hash: str):
        try:
            result = client.shodan.search(f"ssl.cert.fingerprint:{ssl_hash}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchisp", description="Search devices associated with a specific ISP.")
    async def searchisp(interaction: discord.Interaction, isp: str):
        try:
            result = client.shodan.search(f"isp:\"{isp}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchgeo", description="Search devices around specific GPS coordinates.")
    async def searchgeo(interaction: discord.Interaction, latitude: float, longitude: float, radius: int = 10):
        try:
            result = client.shodan.search(f"geo:{latitude},{longitude},{radius}")
            if not result.get('matches', []):
                await interaction.response.send_message("No devices found in the specified region.", ephemeral=True)
                return
            
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="help", description="Displays a list of available commands.")
    async def help_command(interaction: discord.Interaction):
        embed = discord.Embed(title="Available Commands", description="Here are the commands you can use:", color=0x3498db)
        
        # Basic Commands Header
        embed.add_field(name="🟢 Basic Commands", value="Commands for common tasks.", inline=False)
        
        basic_commands_description = "\n".join([
            f"{command}: {description}" 
            for command, description in {
                "/hostinfo": "Get information about a host.",
                "/protocols": "List supported protocols.",
                "/searchcity": "Search Shodan by city.",
                "/searchorg": "Search Shodan by organization.",
                "/searchport": "Search Shodan by port.",
                "/searchcountry": "Search Shodan by country.",
                "/exploitsearch": "Search for known vulnerabilities using a term.",
                "/listtags": "List popular tags.",
                "/searchnetblock": "Search devices in a specific netblock.",
                "/searchproduct": "Search devices associated with a specific product.",
                "/searchssl": "Search for domains associated with a specific SSL certificate hash.",
                "/searchisp": "Search devices associated with a specific ISP.",
                "/searchgeo": "Search devices around specific GPS coordinates."
            }.items()
        ])
        embed.add_field(name="Commands & Descriptions", value=basic_commands_description, inline=False)
        
        # Advanced Search Command Header
        embed.add_field(name="🔴 Advanced Command", value="**Command**: \n`/search [query]`\nSearch Shodan. Click the options for max results and easy mode.", inline=False)
        
        embed.add_field(name="Examples of Basic Searches", value=(
            "- Single IP: `192.168.1.1`\n"
            "- Domain: `example.com`\n"
            "- Product/Service: `nginx`"
        ), inline=False)
        
        embed.add_field(name="Examples of Advanced Queries", value=(
            "- IP Range: `ip:18.9.47.0-18.9.47.255`\n"
            "- Network: `net:18.9.47.0/24`\n"
            "- SSL Cert Subject: `ssl.cert.subject.cn:stellar.mit.edu`\n"
            "- Headers & HTML:\n"
            "  - By Title: `http.title:\"Massachusetts Institute of Technology\"` - Searches for specific titles in HTTP responses.\n"
            "  - By HTML Content: `http.html:'ua-1592615'` - Looks within the content of HTML pages.\n"
            "- Webcams & IoT:\n"
            "  - Search for vulnerable cams like `wyze`, `webcamxp 5`, or more specific like:\n"
            "  -    \"`Server:yawcam\" \"Mime-Type:text/html`\"\n"
            "  - Webcam in ASN: `screenshot.label:webcam asn:AS45102`\n"
            "  - With Screenshot: `has_screenshot:true`"
        ), inline=False)
        
        await interaction.response.send_message(embed=embed, ephemeral=False)

    async def process_shodan_results(interaction: discord.Interaction, result: dict, max_results: int = 10, display_mode: str = "full"):
        matches = result.get('matches', [])
        if matches:
            total = result.get('total', 0)
            info = f"Found {total} results. Here are the top results:\n\n"
            
            responses = []

            for match in matches[:max_results]:  
                ip = match.get('ip_str', 'No IP available.')
                port = match.get('port', 'No port available.')

                # If display mode is easy
                if display_mode == "easy":
                    clickable_link = f"[{ip}:{port}](http://{ip}:{port})"
                    responses.append(clickable_link)
                    continue 

                # If display mode is full
                detailed_info = generate_detailed_info(match)
                responses.append(detailed_info)
            
            message = info + "\n".join(responses)
            await client.send_split_messages(interaction, message)
        else:
            # Extract the user's query from the interaction
            query = ""
            for option in interaction.data.get("options", []):
                if option.get("name") == "query":
                    query = option.get("value", "")
                    break

            # If the query is not empty, include it in the response message
            response_message = "No results found."
            if query:
                response_message = f"No results found for the query: `{query}`."

            await interaction.followup.send(response_message)

    def generate_detailed_info(match: dict) -> str:
        ip = match.get('ip_str', 'No IP available.')
        port = match.get('port', 'No port available.')
        org = match.get('org', 'N/A')
        location = f"{match.get('location', {}).get('country_name', 'N/A')} - {match.get('location', {}).get('city', 'N/A')}"
        product = match.get('product', 'N/A')
        version = match.get('version', 'N/A')
        data = match.get('data', 'No data available.').strip()
        asn = match.get('asn', 'N/A')
        hostnames = ", ".join(match.get('hostnames', [])) or 'N/A'
        os = match.get('os', 'N/A')
        timestamp = match.get('timestamp', 'N/A')
        isp = match.get('isp', 'N/A')
        http_title = match.get('http', {}).get('title', 'N/A')
        ssl_data = match.get('ssl', {}).get('cert', {}).get('subject', {}).get('CN', 'N/A')
        vulns = ", ".join(match.get('vulns', [])) or 'N/A'
        tags = ", ".join(match.get('tags', [])) or 'N/A'
        transport = match.get('transport', 'N/A')
        
        main_link = f"http://{ip}:{port}"
        detailed_info = (f"**IP:** [{ip}]({main_link})\n"
                        f"**Port:** {port}\n"
                        f"**Transport:** {transport}\n"
                        f"**Organization:** {org}\n"
                        f"**Location:** {location}\n"
                        f"**Product:** {product} {version}\n"
                        f"**ASN:** {asn}\n"
                        f"**Hostnames:** {hostnames}\n"
                        f"**OS:** {os}\n"
                        f"**ISP:** {isp}\n"
                        f"**HTTP Title:** {http_title}\n"
                        f"**SSL Common Name:** {ssl_data}\n"
                        f"**Tags:** {tags}\n"
                        f"**Vulnerabilities:** {vulns}\n"
                        f"**Timestamp:** {timestamp}\n"
                        f"**Data:** {data}\n"
                        f"---")
        return detailed_info

    client.run(token)

if __name__ == "__main__":
    config = load_config()
    if check_configurations(config):
        run_discord_bot(config.get("TOKEN"), config.get("SHODAN_KEY"))