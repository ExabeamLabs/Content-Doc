#### Parser Content
```Java
{
Name = mwg-proxy-1
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """"file_sha256_hash":""",""""domain_full":""","""mwg:"""]
    Fields = [
		""""timestamp":"\[({time}[^\]]{1,2000})""",
		"""exabeam_host=({host}[^\s]{1,2000})""",
		"""\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}mwg:""",
		""""user":"(?:|({user}[^"]{1,2000}))"""",
		""""src":"(?:|({src_ip}[^"]{1,2000}))"""",
		""""status":"(?:|({result_code}[^"]{1,2000}))"""",
		""""protocol":"(?:|({protocol}[^"]{1,2000}))"""",
		""""http_user_agent":"(?:|({user_agent}[^"]{1,2000}))"""",
		""""http_method":"(?:|({method}[^"]{1,2000}))"""",
                """"url":"(?:|({full_url}[^"]{1,2000}))"""",
		""""domain_full":"(?:|({web_domain}[^"]{1,2000}))"""",
		""""category":"(?:|({category}[^"]{1,2000}))"""",
		""""bytes_in":"(?:|({bytes_in}[^"]{1,2000}))"""",
		""""bytes_out":"(?:|({bytes_out}[^"]{1,2000}))"""",
		""""cache_status":"(?:|({proxy_action}[^"]{1,2000}))"""",
		""""block_reason":"(?:|({failure_reason}[^"]{1,2000}))"""",
		""""dest":"(?:|({dest_ip}[^"]{1,2000}))"""",
		""""dest_port":"(?:|({dest_port}[^"]{1,2000}))"""",
		""""is_virus":"(?:|({malicious}[^"]{1,2000}))"""",
		""""content_type":"(?:|({mime}[^"]{1,2000}))""""
    ]
  

}
```