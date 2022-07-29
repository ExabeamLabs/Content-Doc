#### Parser Content
```Java
{
Name = s-mimecast-dlp-email-1
    Vendor = Mimecast
    Product = Email Security
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """dproc=TTP Impersonation Protect""", """destinationServiceName =Mimecast Email Security""", """"senderAddress":""", """"recipientAddress":""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"eventTime":"({time}\d{4}-\d{2}-\d{2}T(\d{2}:){2}\d{2}(\+|-)\d+?)"""",
      """"senderAddress":"({sender}[^",]{1,2000}?)"""",
      """"recipientAddress":"({recipient}[^",]{1,2000}?)"""",
      """"senderIpAddress":"({src_ip}[^",]{1,2000}?)"""",
      """"subject":"({subject}[^"]{1,2000}?)"""",
      """"action":"({outcome}[^"]{1,2000}?)"""", 
      """"messageId":"({message_id}[^",]{1,2000}?)"""",
      """"definition":"({additional_info}[^",]{1,2000}?)"""",
      
    ]


}
```