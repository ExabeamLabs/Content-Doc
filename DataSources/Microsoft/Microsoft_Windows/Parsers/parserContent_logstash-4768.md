#### Parser Content
```Java
{
Name = logstash-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["A Kerberos authentication ticket (TGT) was requested", """"event_id":"4768"""", """"account_information-SuppliedRealmName":""""]
    Fields = [
      """"time":"({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""""
      """"host":"({host}[^"]+)\s*"""
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({event_code}4768)""",
      """"account_information-AccountName":"\s*({user}[^"@]+)\s*"""
      """"network_information-ClientAddress":"\s*(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""""
      """"additional_information-ResultCode":"\s*({result_code}[^"]+)\s*""""
      """"account_information-SuppliedRealmName":"\s*({domain}[^"]+)\s*""""
      """"account_information-UserID":"\s*(?:NULL SID|({user_sid}[^"]+))\s*""""
    ]
  }
```