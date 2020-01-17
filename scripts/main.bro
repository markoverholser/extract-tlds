
@load domain-tld
@load shannon-entropy

module ExtractTLDs;

export {
  option unsupported_query_types: set[string] = { "NB" };

  option extract_tld: bool = T;
  option extract_domain: bool = T;
  option extract_subdomain: bool = T;

  option calculate_query_length: bool = T;
  option calculate_domain_length: bool = T;
  option calculate_subdomain_length: bool = T;

  option calculate_domain_shannon_entropy: bool = T;
  option calculate_domain_metric_entropy: bool = T;
  option calculate_subdomain_shannon_entropy: bool = T;
  option calculate_subdomain_metric_entropy: bool = T;
}

# Redefine the DNS::Info record format to add the new columns
redef record DNS::Info += {
  tld: string &log &optional;
  domain: string &log &optional;
  subdomain: string &log &optional;
  query_length: int &log &optional;
  domain_length: int &log &optional;
  subdomain_length: int &log &optional;
  domain_shannon_entropy: double &log &optional;
  subdomain_shannon_entropy: double &log &optional;
  domain_metric_entropy: double &log &optional;
  subdomain_metric_entropy: double &log &optional;
};

# Hook the dns_request event to pull out the TLD, domain, and subdomain on queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
  # print "DNS event";

  # Check to see if the query type is one we want to skip
  if (c$dns$qtype_name in unsupported_query_types) {
    # print fmt("Unsupported query type: %s; skipping", c$dns$qtype_name);

    break;
  }

  # Extract the TLD
  local tld: string = DomainTLD::effective_tld(query);
  # Add it to the record (if enabled)
  if (extract_tld) {
    c$dns$tld = tld;
  }

  # Extract the domain
  local domain: string = DomainTLD::effective_domain(query);
  # Add it to the record (if enabled)
  if (extract_domain) {
    c$dns$domain = domain;
  }

  # Extract the subdomain
  local subdomain: string = sub_bytes(query, 1, |query| - |domain| - 1);
  # Add it to the record (if enabled)
  if (extract_subdomain) {
    c$dns$subdomain = subdomain;
  }

  # Calculate the query length
  if (calculate_query_length)
  {
    c$dns$query_length=|query|;
  }

  # Calculate the domain length
  if (calculate_domain_length)
  {
    c$dns$domain_length = |domain|;
  }

  # Calculate the subdomain length
  if (calculate_subdomain_length)
  {
    c$dns$subdomain_length = |subdomain|;
  }

  # Calculate the domain Shannon entropy
  if (calculate_domain_shannon_entropy)
  {
    c$dns$domain_shannon_entropy = ShannonEntropy::calculate_shannon_entropy(domain);
  }

  # Calculate the domain Metric entropy
  if (calculate_domain_metric_entropy)
  {
    c$dns$domain_metric_entropy = ShannonEntropy::calculate_metric_entropy(domain);
  }

  # Calculate the subdomain Shannon entropy
  if (calculate_subdomain_shannon_entropy)
  {
    c$dns$subdomain_shannon_entropy = ShannonEntropy::calculate_shannon_entropy(subdomain);
  }

  # Calculate subdomain metric entropy
  if (calculate_subdomain_metric_entropy)
  {
    c$dns$subdomain_metric_entropy = ShannonEntropy::calculate_metric_entropy(subdomain);
  }
}
