from whoisquery import WhoisQuery

def main():
    # Basic domain lookup
    whois = WhoisQuery("example.com")
    data = whois.get_whois_data()
    
    if not data.get("error"):
        # Print the parsed data
        print("Domain Name:", data["name"])
        print("Creation Date:", data["created"])
        print("Expiration Date:", data["expires"])
        print("Nameservers:", data["nameservers"])
        print("DNSSEC:", data["dnssec"])
    else:
        print("Error:", data["error"])

if __name__ == "__main__":
    main() 