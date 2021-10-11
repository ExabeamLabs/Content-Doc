#### Parser Content
```Java
{
Name = json-bluecoat-proxy-web-activity
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance 
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """filter_result_CF""", """action_CF""", """BlueCoat_CL""" ]
  Fields = [
    """"TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})"{1,20},""",
    """"Computer"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20},""",
    """"user_CF"{1,20}:"{1,20}(-|({user}[^"]{1,2000}))"{1,20},""",
    """"user_agent_CF"{1,20}:"{1,20}(-|({user_agent}[^"]{1,2000}))"{1,20},""",
    """"country_CF"{1,20}:"{1,20}(None|({country}[^"]{1,2000}))"{1,20},""",
    """"app_CF"{1,20}:"{1,20}(none|({app}[^"]{1,2000}))"{1,20},""",
    """"src_CF"{1,20}:"{1,20}({src_ip}[^"]{1,2000})"{1,20},""",
    """"action_CF"{1,20}:"{1,20}(-|({proxy_action}[^"]{1,2000}))"{1,20},""",
    """"method_CF"{1,20}:"{1,20}({method}[^"]{1,2000})"{1,20},""",
    """"status_CF"{1,20}:"{1,20}({status_code}[^"]{1,2000})"{1,20},""",
    """"uri_query_CF"{1,20}:"{1,20}(-|({uri_query}[^"]{1,2000}))"{1,20},""",
    """"url_CF"{1,20}:"{1,20}(-|({full_url}[^"]{1,2000}))"{1,20},""",
    """"filter_result_CF"{1,20}:"{1,20}(-|({action}[^"]{1,2000}))"{1,20},""",
    """"protocol_CF"{1,20}:"{1,20}(-|({protocol}[^"]{1,2000}))"{1,20},""",
    """"bytes_sent_CF"{1,20}:"{1,20}(-|({bytes_out}[^"]{1,2000}))"{1,20},""",
    """"bytes_recieved_CF"{1,20}:"{1,20}(-|({bytes_in}[^"]{1,2000}))"{1,20},""",
    """"dport_CF"{1,20}:"{1,20}(-|({dest_port}[^"]{1,2000}))"{1,20},""",
    """"proxy_ip_CF"{1,20}:"{1,20}(-|({proxy_ip}[^"]{1,2000}))"{1,20},""",
    """"_ResourceId"{1,20}:"{1,20}(-|({resource_id}[^"]{1,2000}))"{1,20},""",
    """"Type"{1,20}:"{1,20}(-|none|({category}[^"]{1,2000}))"{1,20},""",
    """"categories_CF"{1,20}:"{1,20}({category}[^"]{1,2000})"""",
    """"content_type_CF"{1,20}:"{1,20}(-|({mime}[^"]{1,2000}))"""",
  ]
}
```