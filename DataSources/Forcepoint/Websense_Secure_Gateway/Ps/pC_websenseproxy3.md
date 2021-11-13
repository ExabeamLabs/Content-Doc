#### Parser Content
```Java
{
Name = websense-proxy-3
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ websense_wsg|v""" ]
    Fields = [
      """({host}[\w.\-]{1,2000})\s{1,100}websense_wsg\|v""",
      """websense_wsg\|([^\^]{1,2000}\^){3}(?:-|({action}[^\^]{1,2000}))\^(?:-|({protocol}[^\^]{1,2000}))\^(?:-|({result_code}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|[^\^]{0,2000}?=(({domain}[^\^\\\/=]{1,2000})[\\\/]{1,2000})?({user}[^\^\\\/=]{1,2000}))\^(?:-|({src_ip}[^\^]{1,2000}))\^(?:-|({src_port}[^\^]{1,2000}))\^(?:-|({dest_ip}[^\^]{1,2000}))\^(?:-|({dest_port}[^\^]{1,2000}))\^(?:-|({web_domain}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|({bytes_out}[^\^]{1,2000}))\^(?:-|({bytes_in}[^\^]{1,2000}))\^([^\^]{1,2000}\^){9}(?:-|({method}[^\^]{1,2000}))\^(?:-|({mime}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|({user_agent}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|({full_url}[^\^]{1,2000}?))\s{0,100}(\^|$)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    ]
  

}
```