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
    """"TimeGenerated"+:"+({time}[^"]+)"+,""",
    """"Computer"+:"+({host}[^"]+)"+,""",
    """"user_CF"+:"+(-|({user}[^"]+))"+,""",
    """"user_agent_CF"+:"+(-|({user_agent}[^"]+))"+,""",
    """"country_CF"+:"+(None|({country}[^"]+))"+,""",
    """"app_CF"+:"+(none|({app}[^"]+))"+,""",
    """"src_CF"+:"+({src_ip}[^"]+)"+,""",
    """"action_CF"+:"+(-|({proxy_action}[^"]+))"+,""",
    """"method_CF"+:"+({method}[^"]+)"+,""",
    """"status_CF"+:"+({status_code}[^"]+)"+,""",
    """"uri_query_CF"+:"+(-|({uri_query}[^"]+))"+,""",
    """"url_CF"+:"+(-|({full_url}[^"]+))"+,""",
    """"filter_result_CF"+:"+(-|({action}[^"]+))"+,""",
    """"protocol_CF"+:"+(-|({protocol}[^"]+))"+,""",
    """"bytes_sent_CF"+:"+(-|({bytes_out}[^"]+))"+,""",
    """"bytes_recieved_CF"+:"+(-|({bytes_in}[^"]+))"+,""",
    """"dport_CF"+:"+(-|({dest_port}[^"]+))"+,""",
    """"proxy_ip_CF"+:"+(-|({proxy_ip}[^"]+))"+,""",
    """"_ResourceId"+:"+(-|({resource_id}[^"]+))"+,""",
    """"Type"+:"+(-|none|({category}[^"]+))"+,""",
    """"categories_CF"+:"+({category}[^"]+)"""",
    """"content_type_CF"+:"+(-|({mime}[^"]+))"""",
  ]
}
```