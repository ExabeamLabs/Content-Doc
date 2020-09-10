#### Parser Content
```Java
{
Name = logstash-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["A Kerberos service ticket was requested", """"event_id":"4769"""", """"additional_information-TicketOptions":""""]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """"time":"({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""""
      """"host":"({host}[^"]+)\s*"""
      """({event_code}4769)""",
      """"account_information-AccountName":"\s*({user}[^"@]+)\s*"""
      """"account_information-AccountDomain":"\s*({domain}[^"]+)\s*"""
      """"service_information-ServiceName":"\s*({dest_host}\S+\$)\s*""""
      """"service_information-ServiceName":"\s*({service_name}[^"]+)\s*""""
      """"network_information-ClientAddress":"\s*(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""""
      """"additional_information-FailureCode":"\s*({result_code}[^"]+)\s*""""
      """"additional_information-TicketOptions":"\s*({ticket_options}[^"]+)""""
      """"additional_information-TicketEncryptionType":"\s*({ticket_encryption_type}[^"]+)\s*""""
    ]
  }
```