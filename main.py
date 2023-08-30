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

    async def send_split_messages(self, interaction, message: str):
        """Sends a message, and if it's too long for Discord, splits it."""
        # Handle empty messages
        if not message.strip():
            logger.warning("Attempted to send an empty message.")
            return

        try:
            # Split message into manageable chunks
            chunks = [message[i:i+self.discord_message_limit] for i in range(0, len(message), self.discord_message_limit)]
            
            # Send all chunks as follow-ups
            for chunk in chunks:
                try:
                    await interaction.followup.send(chunk, ephemeral=False)
                except Exception as e:
                    logger.error(f"Failed to send a message chunk in follow-up. Error: {e}")
        except Exception as e:
            logger.error(f"Failed to send a message. Error: {e}")

async def handle_errors(interaction, error, error_type="Error"):
    try:
        await interaction.response.send_message(f"{error_type}: {error}", ephemeral=True)
    except discord.HTTPException as http_err:
        logger.warning(f"HTTP error while responding to {interaction.user}: {http_err}")
        try:
            await interaction.followup.send(f"{error_type}: {error}")
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
    async def search(interaction: discord.Interaction, query: str):
        # Acknowledge the interaction immediately
        await interaction.response.defer(ephemeral=False)
        
        try:
            query = query.strip()  
            result = client.shodan.search(query)
            matches = result.get('matches', [])

            if matches:
                reply = ""
                for i, match in enumerate(matches[:5]): 
                    ip = match.get('ip_str', 'Unknown IP')
                    port = match.get('port', 'Unknown Port')
                    org = match.get('org', 'Unknown Org')
                    location = match.get('location', {}).get('country', 'Unknown Country')
                    data = match.get('data', 'No data available.')
                    product = match.get('product', 'Unknown Product')
                    version = match.get('version', 'Unknown Version')
                    os = match.get('os', 'Unknown OS')

                    reply += f"Result {i+1}:\n"
                    reply += f"IP: {ip}, Port: {port}\n"
                    reply += f"Organization: {org}\n"
                    reply += f"Location: {location}\n"
                    reply += f"Product: {product}, Version: {version}, OS: {os}\n"
                    reply += f"Data: {data}\n\n"

                await client.send_split_messages(interaction, reply)
            else:
                await interaction.followup.send("No matches found for the given query.")

        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchcity", description="Search Shodan by city.")
    async def searchcity(interaction: discord.Interaction, city: str):
        city = city.strip()  
        
        try:
            result = client.shodan.search(f"city:\"{city}\"")
            matches = result.get('matches', [])

            if matches:
                reply = ""
                for i, match in enumerate(matches[:5]):  # Displaying first 5 matches here
                    ip = match.get('ip_str', 'Unknown IP')
                    port = match.get('port', 'Unknown Port')
                    org = match.get('org', 'Unknown Org')
                    location = match.get('location', {}).get('country', 'Unknown Country')
                    data = match.get('data', 'No data available.').strip()  # Removing leading/trailing whitespace
                    product = match.get('product', 'Unknown Product')
                    version = match.get('version', 'Unknown Version')
                    os = match.get('os', 'Unknown OS')

                    reply += f"Result {i+1}:\n"
                    reply += f"IP: {ip}, Port: {port}\n"
                    reply += f"Organization: {org}\n"
                    reply += f"Location: {location}\n"
                    reply += f"Product: {product}, Version: {version}, OS: {os}\n"
                    reply += f"Data: {data}\n\n"
            else:
                reply = f"No results for city: {city}"

            await interaction.response.send_message(reply, ephemeral=False)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchorg", description="Search Shodan by organization.")
    async def searchorg(interaction: discord.Interaction, organization: str):
        try:
            await interaction.response.defer(ephemeral=False)

            result = client.shodan.search(f"org:\"{organization}\"")
            matches = result.get('matches', [])

            if matches:
                top_matches = matches[:5]
                reply = "Top 5 Results:\n\n"

                for match in top_matches:
                    ip_str = match.get('ip_str', 'Unknown IP')
                    port = match.get('port', 'Unknown Port')
                    org = match.get('org', 'Unknown Organization')
                    location = match.get('location', {})
                    country_name = location.get('country_name', 'Unknown Country')
                    city = location.get('city', 'Unknown City')
                    data = match.get('data', 'No data available.')

                    reply += (f"**IP:** {ip_str}\n"
                            f"**Port:** {port}\n"
                            f"**Organization:** {org}\n"
                            f"**Country:** {country_name}\n"
                            f"**City:** {city}\n\n"
                            f"**Data:**\n{data}\n\n"
                            f"{'-'*30}\n\n")

                await interaction.followup.send(reply, ephemeral=True)

            else:
                await interaction.followup.send(f"No results for organization: {organization}", ephemeral=True)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
              
    @client.tree.command(name="searchport", description="Search Shodan by port.")
    async def searchport(interaction: discord.Interaction, port: int):
        try:
            result = client.shodan.search(f"port:{port}")
            matches = result.get('matches', [])
            
            if matches:
                replies = [f"IP: {match['ip_str']} - Port: {port} - Data: {match.get('data', 'No data available.')}" for match in matches[:5]]
                reply = "\n\n".join(replies)
            else:
                reply = f"No results for port: {port}"
            
            await client.send_split_messages(interaction, reply)
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
            matches = result.get('matches', [])
            
            if matches:
                replies = []
                for match in matches[:5]:
                    ip = match.get('ip_str', 'Unknown IP')
                    port = match.get('port', 'Unknown Port')
                    org = match.get('org', 'N/A')
                    city = match.get('location', {}).get('city', 'N/A')
                    data = match.get('data', 'No data available.').strip()
                    
                    detailed_info = (f"**IP:** {ip}\n"
                                    f"**Port:** {port}\n"
                                    f"**Organization:** {org}\n"
                                    f"**City:** {city}\n\n"
                                    f"**Data:**\n{data}\n"
                                    f"---")
                    replies.append(detailed_info)

                message = "\n".join(replies)
                await client.send_split_messages(interaction, message)
            else:
                await interaction.followup.send(f"No results found for country code: {country_code}")
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
        try:
            if not 1 <= size <= 100:
                await interaction.response.send_message(
                    "The provided size is out of bounds. Please specify a value between 1 and 100.",
                    ephemeral=True
                )
                return

            tags = client.shodan.exploits.tags(size=size)
            tag_list = ", ".join([tag['value'] for tag in tags['matches']])
            await interaction.followup.send(f"Here are the top {size} popular exploit tags: {tag_list}")
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
        embed.add_field(name="🔴 Advanced Command", value="**Command**: \n`/search [query]`\nSearch Shodan with both basic and advanced query syntax.", inline=False)
        
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
            "  - Webcam in ASN: `screenshot.label:webcam asn:AS45102`\n"
            "  - With Screenshot: `has_screenshot:true`"
        ), inline=False)
        
        await interaction.response.send_message(embed=embed, ephemeral=False)

    async def process_shodan_results(interaction: discord.Interaction, result: dict):
        matches = result.get('matches', [])
        if matches:
            total = result.get('total', 0)
            info = f"Found {total} results. Here are the top results:\n\n"
            
            responses = []
            for match in matches[:5]:  # Limiting to top 5 matches
                data = match.get('data', 'No data available.').strip()
                ip = match.get('ip_str', 'No IP available.')
                port = match.get('port', 'No port available.')
                org = match.get('org', 'N/A')
                location = f"{match.get('location', {}).get('country_name', 'N/A')} - {match.get('location', {}).get('city', 'N/A')}"
                product = match.get('product', 'N/A')
                version = match.get('version', 'N/A')
                
                detailed_info = (f"**IP:** {ip}\n"
                                f"**Port:** {port}\n"
                                f"**Organization:** {org}\n"
                                f"**Location:** {location}\n"
                                f"**Product:** {product} {version}\n"
                                f"**Data:** {data}\n"
                                f"---")
                responses.append(detailed_info)
            
            message = info + "\n".join(responses)
            await client.send_split_messages(interaction, message)
        else:
            await interaction.followup.send("No results found.")

    client.run(token)

if __name__ == "__main__":
    config = load_config()
    if check_configurations(config):
        run_discord_bot(config.get("TOKEN"), config.get("SHODAN_KEY"))