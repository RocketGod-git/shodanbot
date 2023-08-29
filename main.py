import json
import logging
import discord
from discord import Embed
import shodan

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

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
            if len(message) <= self.discord_message_limit:
                await interaction.response.send_message(message, ephemeral=False)
            else:
                # Split message into manageable chunks
                chunks = [message[i:i+self.discord_message_limit] for i in range(0, len(message), self.discord_message_limit)]
                
                # Respond to the initial interaction with the first chunk
                await interaction.response.send_message(chunks[0], ephemeral=False)
                
                # Send the remaining chunks as follow-ups
                for chunk in chunks[1:]:
                    try:
                        await interaction.followup.send(chunk)
                    except Exception as e:
                        logger.error(f"Failed to send a message chunk in follow-up. Error: {e}")
        except Exception as e:
            logger.error(f"Failed to send a message. Error: {e}")

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
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="protocols", description="List supported protocols.")
    async def protocols(interaction: discord.Interaction):
        try:
            protocol_list = client.shodan.protocols()

            # Formatting the protocols for better readability
            formatted_protocols = "\n".join([f"- {protocol}" for protocol in protocol_list])

            await client.send_split_messages(interaction, formatted_protocols)

        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="search", description="Search Shodan.")
    async def search(interaction: discord.Interaction, query: str):
        try:
            result = client.shodan.search(query)
            matches = result.get('matches', [])

            if matches:
                # Compile a detailed report from the first few matches
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
                reply = "No matches found."

            await client.send_split_messages(interaction, reply)

        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchcity", description="Search Shodan by city.")
    async def searchcity(interaction: discord.Interaction, city: str):
        try:
            result = client.shodan.search(f"city:\"{city}\"")
            matches = result.get('matches', [])

            if matches:
                # Let's compile a detailed report from the first few matches (you can adjust the number as needed)
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

            # Respond directly to the interaction
            await interaction.response.send_message(reply, ephemeral=False)

        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchorg", description="Search Shodan by organization.")
    async def searchorg(interaction: discord.Interaction, organization: str):
        try:
            # Acknowledge the interaction first (deferred response)
            await interaction.response.defer(ephemeral=False)

            result = client.shodan.search(f"org:\"{organization}\"")
            matches = result.get('matches', [])

            if matches:
                # Limit to the top 5 results
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
                            f"{'-'*30}\n\n")  # Separator for clarity

                await interaction.followup.send(reply, ephemeral=True)

            else:
                await interaction.followup.send(f"No results for organization: {organization}", ephemeral=True)

        except shodan.APIError as e:
            await interaction.followup.send(f"Shodan API Error: {e}", ephemeral=True)

        except Exception as e:
            await interaction.followup.send(f"Error: {e}", ephemeral=True)

    @client.tree.command(name="searchport", description="Search Shodan by port.")
    async def searchport(interaction: discord.Interaction, port: int):
        try:
            result = client.shodan.search(f"port:{port}")
            matches = result.get('matches', [])
            
            if matches:
                # Create a list of strings with IP, Port, and Data for the top 5 matches
                replies = [f"IP: {match['ip_str']} - Port: {port} - Data: {match.get('data', 'No data available.')}" for match in matches[:5]]
                reply = "\n\n".join(replies)
            else:
                reply = f"No results for port: {port}"
            
            await client.send_split_messages(interaction, reply)
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchcountry", description="Search Shodan by country.")
    async def searchcountry(interaction: discord.Interaction, country: str):
        try:
            result = client.shodan.search(f"country:\"{country}\"")
            matches = result.get('matches', [])
            if matches:
                # Gather meaningful data from the match
                match = matches[0]
                ip_str = match.get('ip_str', 'Unknown IP')
                port = match.get('port', 'Unknown Port')
                org = match.get('org', 'Unknown Organization')
                location = match.get('location', {})
                country_name = location.get('country_name', 'Unknown Country')
                city = location.get('city', 'Unknown City')
                data = match.get('data', 'No data available.')

                reply = (f"**IP:** {ip_str}\n"
                        f"**Port:** {port}\n"
                        f"**Organization:** {org}\n"
                        f"**Country:** {country_name}\n"
                        f"**City:** {city}\n\n"
                        f"**Data:**\n{data}")

            else:
                reply = f"No results for country: {country}"

            await client.send_split_messages(interaction, reply)

        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="exploitsearch", description="Search for known vulnerabilities using a term.")
    async def exploitsearch(interaction: discord.Interaction, term: str):
        try:
            exploit_search = client.shodan.exploits.search(term)
            if 'matches' in exploit_search and exploit_search['matches']:
                first_exploit = exploit_search['matches'][0]
                
                # Extract meaningful data from the exploit result
                description = first_exploit.get('description', 'No description available.')
                source = first_exploit.get('source', 'Unknown source')
                date = first_exploit.get('date', 'Unknown date')
                exploit_type = first_exploit.get('type', 'Unknown type')

                reply = (f"**Description:** {description}\n"
                        f"**Source:** {source}\n"
                        f"**Date:** {date}\n"
                        f"**Type:** {exploit_type}")

                await client.send_split_messages(interaction, reply)
            else:
                await interaction.followup.send("No exploits found for that term.")
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="listtags", description="List popular tags.")
    async def listtags(interaction: discord.Interaction, size: int = 10):
        try:
            # Ensure the size is within an acceptable range
            if not 1 <= size <= 100:
                await interaction.response.send_message("Please provide a size between 1 and 100.", ephemeral=True)
                return

            tags = client.shodan.exploits.tags(size=size)
            tag_list = ", ".join([tag['value'] for tag in tags['matches']])
            await interaction.followup.send(f"Popular tags: {tag_list}")
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchnetblock", description="Search devices in a specific netblock.")
    async def searchnetblock(interaction: discord.Interaction, netblock: str):
        try:
            result = client.shodan.search(f"net:{netblock}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
                    
    @client.tree.command(name="searchproduct", description="Search devices associated with a specific product.")
    async def searchproduct(interaction: discord.Interaction, product: str):
        try:
            result = client.shodan.search(f"product:{product}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchssl", description="Search for domains associated with a specific SSL certificate hash.")
    async def searchssl(interaction: discord.Interaction, ssl_hash: str):
        try:
            result = client.shodan.search(f"ssl.cert.fingerprint:{ssl_hash}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchisp", description="Search devices associated with a specific ISP.")
    async def searchisp(interaction: discord.Interaction, isp: str):
        try:
            result = client.shodan.search(f"isp:\"{isp}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="searchgeo", description="Search devices around specific GPS coordinates.")
    async def searchgeo(interaction: discord.Interaction, latitude: float, longitude: float, radius: int = 10):
        try:
            result = client.shodan.search(f"geo:{latitude},{longitude},{radius}")
            if not result.get('matches', []):
                await interaction.response.send_message("No devices found in the specified region.", ephemeral=True)
                return
            
            await process_shodan_results(interaction, result)
            
        except shodan.APIError as e:
            try:
                await interaction.response.send_message(f"Shodan API Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Shodan API Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")
        except Exception as e:
            try:
                await interaction.response.send_message(f"Error: {e}", ephemeral=True)
            except Exception:
                try:
                    await interaction.followup.send(f"Error: {e}")
                except Exception as followup_error:
                    logger.error(f"Failed to send followup: {followup_error}")

    @client.tree.command(name="help", description="Displays a list of available commands.")
    async def help_command(interaction: discord.Interaction):
        # Create an Embed object for the help message
        embed = discord.Embed(title="Available Commands", description="Here are the commands you can use:", color=0x3498db)
        
        # Manually add commands to the embed
        commands = {
            "/hostinfo": "Get information about a host.",
            "/protocols": "List supported protocols.",
            "/search": "Search Shodan.",
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
        }
        
        for command, description in commands.items():
            embed.add_field(name=command, value=description, inline=False)
        
        # Send the embed as a response to the interaction
        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def process_shodan_results(interaction: discord.Interaction, result: dict):
        matches = result.get('matches', [])
        if matches:
            # Compose a message with more context about the results
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