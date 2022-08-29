#### Parser Content
```Java
{
Name = zscaler-web-activity-7
 Vendor = Zscaler
 Product = Zscaler Internet Access
 Lms = Direct
 DataType = "web-activity"
 TimeFormat = "MMM dd HH:mm:ss yyyy"
 Conditions = [ """vendor=Zscaler""","""product=NSS""","""avg_duration=""","""ip_protocol=""","""devicehostname=""","""client_src_ip=""","""client_dst_ip=""" ]
 Fields = [
  """({time}\w{3}\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
  """server_dst_port=({dest_port}\d{1,5})""",
  """client_src_port=({src_port}\d{1,5})""",
  """department=({department}[^\=]{1,2000}?)\s{1,100}\w+=""",
  """tunnel_src_port=({tunnel_src_port}\d{1,5})""",
  """locationname=({location}[^\=]{1,2000}?)\s{1,100}\w+=""",
  """client_src_ip=({src_ip}[a-fA-F:\d.]{1,2000})""",
  """server_dst_ip=({dest_ip}[a-fA-F:\d.]{1,2000})""",
  """tunnel_src_ip=({tunnel_src_ip}[a-fA-F:\d.]{1,2000})""",
  """action=({action}[^=]{1,2000}?)\s""",
  """service=({service}[^=]{1,2000}?)\s""",
  """application=({app}[^=]{1,2000}?)\s""",
  """ip_protocol=({protocol}[^=]{1,2000}?)\s""",
  """url_cat=({category}[^=]{1,2000}?)\s""",
  """rule=({rule}[^\=]{1,2000}?)\s\w+=""",
  """inbytes=({bytes_in}\d{1,100})""",
  """outbytes=({bytes_out}\d{1,100})""",
  """duration=({duration}[^=]{1,2000}?)\s""",
  """sessions=({session_id}[^\s]{1,2000})""",
  """ips_policy=(None|({policy}[^\s]{1,2000}))\s""",
  """threat_cat=(None|({threat_category}[^\s]{1,2000}))""",
  """threatname=(None|({threat_name}[^\s]{1,2000}))""",
  """deviceowner=(NA|({device_owner}[^\s]{1,2000}))""",
  """devicehostname=(NA|({src_host}[^=]{1,2000}?))\s""",
  """deviceos=(NA|({os}[^=]{1,2000}?)\s)\w+=""",
]



}
```