#### Parser Content
```Java
{
Name = ping-web-activity
  Vendor = Ping Identity
  Product = PingAccess
  DataType ="web-activity"
  Lms = Direct
  TimeFormat = "yyyy-mm-dd'T'HH:mm:ss"
  Conditions = [ """<<Custom condition cont-8024>>""" ] 
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)(,\d+)?\|\s*({id}[^\|]+)?\|\s*({transcation_id}[^\|]+)?\|\s*([^\|]+\|){3}\s*({action}[^\|]+)\|\s*({user}[^\|]+)?\|\s*({authentication}[^\|]+)?\|\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\|\s*({method}[^\|]+)\|\s*({uri_path}[^\|]+)\|({result_code}[^\|]+)\|\s*([^\|]+)\|( |\s*({failure_reason}[^\|]+))\|"""
  ]
}
```