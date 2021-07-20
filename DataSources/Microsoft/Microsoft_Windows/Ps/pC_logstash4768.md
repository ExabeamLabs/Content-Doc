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
      """"time":"({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""""
      """"host":"({host}[^"]{1,2000})\s{0,100}"""
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """({event_code}4768)""",
      """"account_information-AccountName":"\s{0,100}({user}[^"@]{1,2000})\s{0,100}"""
      """"network_information-ClientAddress":"\s{0,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""""
      """"additional_information-ResultCode":"\s{0,100}({result_code}[^"]{1,2000})\s{0,100}""""
      """"account_information-SuppliedRealmName":"\s{0,100}({domain}[^"]{1,2000})\s{0,100}""""
      """"account_information-UserID":"\s{0,100}(?:NULL SID|({user_sid}[^"]{1,2000}))\s{0,100}"""",
      """"service_information-ServiceName":"({service_name}[^"]{1,2000})""",
      """"additional_information-TicketEncryptionType":"({ticket_encryption_type}[^"]{1,2000})""",
      """"additional_information-TicketOptions":"({ticket_options}[^"]{1,2000})"""
    ]
    DupFields = ["host->dest_host"]
  }
```