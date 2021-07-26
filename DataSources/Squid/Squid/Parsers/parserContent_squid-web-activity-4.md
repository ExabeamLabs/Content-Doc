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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """http_username":"(-|({user}[^"]{1,2000}))"""",
      """http_method":"({method}[^"]{1,2000})"""",
      """squid_request_status":"({proxy_action}[^"]{1,2000})"""",
      """http_url":"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))""",
      """http_status_code"{0,20}:({result_code}\d{1,100})""",
      """ip_server":"(-|({dest_ip}[a-fA-F\d.:]{1,2000}))"""",
      """ip_client":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
      """http_reply_size":({bytes_out}\d{1,100})""",
      """http_received_size":({bytes_in}\d{1,100})""",
      """http_mime_type":"(-|({mime}[^"]{1,2000}?))","""
   ]
}
```