#### Parser Content
```Java
{
Name = squid-web-activity-4
   Vendor = Squid
   Product = Squid
   Lms = Direct
   DataType = "web-activity"
   TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSZ"""
   Conditions = [  """http_method""",   """http_status_code""",       """squid_request_status"""    ]
   Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """http_username":"(-|({user}[^"]+))"""",
      """http_method":"({method}[^"]+)"""",
      """squid_request_status":"({proxy_action}[^"]+)"""",
      """http_url":"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))""",
      """http_status_code"*:({result_code}\d+)""",
      """ip_server":"(-|({dest_ip}[a-fA-F\d.:]+))"""",
      """ip_client":"({src_ip}[a-fA-F\d.:]+)"""",
      """http_reply_size":({bytes_out}\d+)""",
      """http_received_size":({bytes_in}\d+)""",
      """http_mime_type":"(-|({mime}[^"]+?))","""
   ]
}
```