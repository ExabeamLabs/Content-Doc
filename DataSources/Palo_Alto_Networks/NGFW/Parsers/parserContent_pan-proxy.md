#### Parser Content
```Java
{
Name = pan-proxy
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,url,""", """(9999)"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\-\.]+)[\s\-]+\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]*,THREAT,url,""",
    """THREAT,("[^"]*",|[^,]*,){55}({host}[\w\-\.]+)""",
    """:\d\d:\d\d\s+({host}[\w.-]+)\s""",
    """THREAT,url,\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({src_ip}[a-fA-F\d.:]+),({dest_ip}[a-fA-F\d.:]+),""",
    """THREAT,url,([^,]*,){5,8}(({domain}[^\\,]+)\\)(|({user}[^,]+)),""",
    """THREAT,url,([^,]*,){4}((\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}
```