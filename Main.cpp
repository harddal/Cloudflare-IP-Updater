#include <chrono>
#include <string>
#include <vector>

#include "cpr/cpr.h"
#include "nlohmann/json.hpp"
#include "tinyxml2/tinyxml2.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

static bool DebugOutput = false;

#define cmdline_option_exists(x) CmdOptionExists(argv, argv + argc, x)
#define cmdline_get_option(x) GetCmdOption(argv, argv + argc, x)

bool CmdOptionExists(char **begin, char **end, const std::string &option)
{
	return std::find(begin, end, option) != end;
}

char* GetCmdOption(char **begin, char **end, const std::string &option)
{
	char **itr = std::find(begin, end, option);

	if (itr != end && ++itr != end)
	{
		return *itr;
	}

	return 0;
}

void ClearScreen(HANDLE console)
{
	COORD topLeft = { 0, 0 };
	CONSOLE_SCREEN_BUFFER_INFO screen;
	DWORD written;

	GetConsoleScreenBufferInfo(console, &screen);
	FillConsoleOutputCharacterA(
		console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);

	FillConsoleOutputAttribute(
		console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
		screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);

	SetConsoleCursorPosition(console, topLeft);
}

bool stob(std::string s, bool throw_on_error = true)
{
	auto result = false;

	std::istringstream is(s);

	is >> result;

	if (is.fail())
	{
		is.clear();
		is >> std::boolalpha >> result;
	}

	if (is.fail() && throw_on_error)
	{
		throw std::invalid_argument(s.append(" is not convertable to bool"));
	}

	return result;
}

struct DNS_Entry
{
	std::string
		prefix,
		type,
		proxied,
		ttl,
		comment,
		token;

	DNS_Entry(std::string prefix, std::string type, std::string proxied, std::string ttl, std::string comment, std::string token)
	{
		this->prefix = prefix;
		this->type = type;
		this->proxied = proxied;
		this->ttl = ttl;
		this->comment = comment;
		this->token = token;
	}
};

struct CloudflareData
{
	std::string
		api_token,
		dns_token,
		dns_record;

	std::vector<DNS_Entry> entries;
};

bool LoadData(CloudflareData &data)
{
	auto xml = std::make_shared<tinyxml2::XMLDocument>();

	if (xml->LoadFile("data.dns") != tinyxml2::XML_SUCCESS)
	{
		spdlog::error("Failed to load DNS entry data file!");

		return false;
	}

	try
	{
		auto root = xml->FirstChildElement();

		auto element = root->FirstChildElement();
		data.api_token = element->GetText();

		element = element->NextSiblingElement();
		data.dns_token = element->GetText();

		element = element->NextSiblingElement();
		data.dns_record = element->GetText();

		for (element = element->NextSiblingElement()->FirstChildElement(); element != nullptr; element = element->NextSiblingElement())
		{
			data.entries.emplace_back(DNS_Entry(element->Attribute("prefix"), element->Attribute("type"), element->Attribute("proxied"), element->Attribute("ttl"), element->Attribute("comment"), element->Attribute("token")));
		}
	}
	catch (...)
	{
		spdlog::error("Failed to parse DNS entry data file!");

		return false;
	}

	spdlog::info("Loaded DNS entry data file...");

	return true;
}

int main(int argc, char** argv) 
{
	bool active = true;

	HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);

	std::string
		ip_address = "invalid",
		old_ip_address = "0.0.0.0";

	unsigned int update_rate = 30;

	if (cmdline_option_exists("-r"))
	{
		update_rate = atoi(cmdline_get_option("-r"));
	}
	if (cmdline_option_exists("-d"))
	{
		DebugOutput = true;
	}

	auto log_console_sink = std::make_shared<spdlog::sinks::wincolor_stdout_sink_mt>();
	log_console_sink->set_level(spdlog::level::trace);

	auto log_file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("output.log", true);
	log_file_sink->set_level(spdlog::level::trace);

	auto log = std::make_shared<spdlog::logger>(spdlog::logger("core", { log_console_sink, log_file_sink }));
	set_default_logger(log);
	log->set_level(spdlog::level::trace);

	spdlog::info("Cloudflare DNS Entry Auto Update Tool v2.0");

	CloudflareData dns_data;

	if (!LoadData(dns_data))
	{
		log->flush();
		spdlog::shutdown();

		return 0;
	}

	if (DebugOutput)
	{
		spdlog::debug("Loaded API Token:   {0}", dns_data.api_token);
		spdlog::debug("Loaded DNS Token:   {0}", dns_data.dns_token);
		spdlog::debug("Loaded Zone Record: {0}", dns_data.dns_record);

		for (auto entry : dns_data.entries)
		{
			spdlog::debug("Loaded DNS Entry:   {0}, {1}, {2}, {3}", entry.prefix, entry.type, entry.proxied, entry.token);
		}
	}

	auto timer_start = std::chrono::high_resolution_clock::now();

	bool first_run = true;

	while (active)
	{
		if (!first_run)
		{
			auto timer_end = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double, std::milli> elasped = timer_end - timer_start;
			if (elasped.count() < static_cast<double>(update_rate) * 1000.0)
			{
				continue;
			}
			else
			{
				timer_start = std::chrono::high_resolution_clock::now();
			}
		}
		else
		{
			first_run = false;
		}

		bool error = false;

		cpr::Response response = cpr::Get(cpr::Url{ "https://api.ipify.org?format=json" });

		if (response.status_code == 200L)
		{
			std::string json = response.text;
			std::string sub = json.substr(json.find_first_of(':') + 2);
			ip_address = sub.substr(0, sub.length() - 2);

			if (ip_address == old_ip_address)
			{
				if (DebugOutput)
				{
					spdlog::debug("Public IP has not changed since last check");
				}
				
				continue;
			}
			else
			{
				ClearScreen(console_handle);

				spdlog::info("Retrieved new public IP address: {0}", ip_address);
			}

			std::vector<nlohmann::json> payload;
			std::vector<std::string> records;

			for (auto entry : dns_data.entries)
			{
				payload.emplace_back(nlohmann::json{
						{ "content", ip_address},
						{ "name", entry.prefix },
						{ "proxied", stob(entry.proxied, false) },
						{ "type", entry.type },
						{ "comment", entry.comment },
						{ "id", entry.token },
						{ "ttl", std::stoi(entry.ttl) }
					});

				records.emplace_back(std::string(dns_data.dns_record + entry.token));
			}

			for (unsigned int i = 0; i < payload.size(); i++)
			{
				cpr::CurlHolder curl_data;

				cpr::Response post = cpr::Put(
					cpr::Url{ records.at(i) },
					cpr::Bearer{ dns_data.dns_token },
					cpr::Header{ {"Content-Type", "application/json"} },
					cpr::Body{ payload.at(i).dump() });

				if (post.status_code == 200)
				{
					spdlog::info("POST operation for entry \'{0}\' successful!", dns_data.entries.at(i).prefix);

					if (DebugOutput)
					{
						nlohmann::json response_json = nlohmann::json::parse(post.text);
						spdlog::debug("Cloudflare API response:\n{0}", response_json.dump(4));
					}
				}
				else
				{
					error = true;

					spdlog::error("POST operation for entry \'{0}\' failed with code: {1}", dns_data.entries.at(i).prefix, post.status_code);

					if (DebugOutput)
					{
						spdlog::debug("Cloudflare API response:\n{0}", post.text);
					}
				}
			}

			if (error)
			{
				ip_address = "invalid";
			}
			else
			{
				old_ip_address = ip_address;
			}
		}
		else
		{
			spdlog::error("Failed to retrieve public IP address, code: {0}", response.status_code);

			ip_address = "invalid";
		}

		log->flush();
	}

	log->flush();
	spdlog::shutdown();

	return 0;
}
