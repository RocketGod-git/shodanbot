# ShodanBot
A Discord bot to interact with the Shodan API, allowing users to fetch information about devices, services, and vulnerabilities.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rocketgod-git/shodanbot.git
   cd shodanbot
   ```

2. **Windows Users**: Run the `run.bat` file to set up the virtual environment and install necessary dependencies.

   **Linux Users**: Make `run.sh` executable with `chmod +x run.sh` and then run it with `./run.sh`.

## Configuration

Before running the bot, you need to set up the `config.json` file:

- `TOKEN`: Your Discord bot token.
- `SHODAN_API_KEY`: Your Shodan API key.

Example:
```json
{
    "TOKEN": "YOUR_DISCORD_BOT_TOKEN",
    "SHODAN_API_KEY": "YOUR_SHODAN_API_KEY"
}
```

## Usage

Invite the bot to your server and use the available commands to interact with Shodan. Here's a detailed list of the available commands:

- `/hostinfo <IP>`: Get information about a host.
- `/protocols`: List supported protocols.
- `/search <query>`: Search Shodan.
- `/searchcity <city>`: Search Shodan by city.
- `/searchorg <organization>`: Search Shodan by organization.
- `/searchport <port>`: Search Shodan by port.
- `/searchcountry <country>`: Search Shodan by country.
- `/exploitsearch <term>`: Search for known vulnerabilities using a term.
- `/listtags`: List popular tags on Shodan.
- `/searchnetblock <netblock>`: Search devices in a specific netblock.
- `/searchproduct <product>`: Search devices associated with a specific product.
- `/searchssl <SSL hash>`: Search for domains associated with a specific SSL certificate hash.
- `/searchisp <ISP>`: Search devices associated with a specific ISP.
- `/searchgeo <latitude> <longitude> <radius>`: Search devices around specific GPS coordinates.

For more advanced usage or to get more information about a particular command, use the bot's help command or refer to the bot's command descriptions in Discord.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License

[LICENSE](LICENSE)


![rocketgod_logo](https://github.com/RocketGod-git/shodanbot/assets/57732082/7929b554-0fba-4c2b-b22d-6772d23c4a18)
