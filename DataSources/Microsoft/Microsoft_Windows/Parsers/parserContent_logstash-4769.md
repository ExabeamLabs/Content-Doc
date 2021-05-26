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
      """"time":"({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""""
      """"host":"({host}[^"]{1,2000})\s{0,100}"""
      """({event_code}4769)""",
      """"account_information-AccountName":"\s{0,100}({user}[^"@]{1,2000})\s{0,100}"""
      """"account_information-AccountDomain":"\s{0,100}({domain}[^"]{1,2000})\s{0,100}"""
      """"service_information-ServiceName":"\s{0,100}({dest_host}\S+\$)\s{0,100}""""
      """"service_information-ServiceName":"\s{0,100}({service_name}[^"]{1,2000})\s{0,100}""""
      """"network_information-ClientAddress":"\s{0,100}(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""""
      """"additional_information-FailureCode":"\s{0,100}({result_code}[^"]{1,2000})\s{0,100}""""
      """"additional_information-TicketOptions":"\s{0,100}({ticket_options}[^"]{1,2000})""""
      """"additional_information-TicketEncryptionType":"\s{0,100}({ticket_encryption_type}[^"]{1,2000})\s{0,100}""""
    ]
  }
```