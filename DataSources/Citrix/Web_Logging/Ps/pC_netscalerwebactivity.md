#### Parser Content
```Java
{
Name = netscaler-web-activity
    Vendor = Citrix
    Product = Web Logging
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """<cont-5991 conditions>""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}(?:-|({host}\S+))\s{1,100}(?:-|({user}\S+))\s{1,100}(?:-|({protocol}\S+))\s{1,100}(?:-|({src_ip}\S+))\s{1,100}(?:-|({src_port}\S+))\s{1,100}(?:-|({method}\S+))\s{1,100}(?:-|({uri_path}\S+))\s{1,100}(?:-|({uri_query}\S+))\s{1,100}(?:-|({result_code}\S+))\s{1,100}(?:-|({bytes_in}\S+))\s{1,100}(?:-|({bytes_out}\S+))\s{1,100}(\S+\s{1,100}){2}(?:-|({user_agent}\S+))\s{1,100}\S+\s{1,100}(?:-|({referrer}\S+))\s{0,100}$""",
    ]
  

}
```