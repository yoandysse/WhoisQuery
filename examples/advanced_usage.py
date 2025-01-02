from whoisquery import WhoisQuery
import json

def check_multiple_domains(domains):
    results = {}
    for domain in domains:
        try:
            whois = WhoisQuery(domain)
            results[domain] = whois.get_whois_data()
        except Exception as e:
            results[domain] = {"error": str(e)}
    
    return results

def main():
    # Check multiple domains
    domains = ["google.com", "github.com", "python.org"]
    results = check_multiple_domains(domains)
    
    # Print results as JSON
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 