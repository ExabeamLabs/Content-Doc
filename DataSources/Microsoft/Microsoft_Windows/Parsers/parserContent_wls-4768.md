#### Parser Content
```Java
{
Name = wls-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="4768""""]
    Fields = [
      """Computer="{1,20}({host}[^"]+)"""",
      """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """TargetUserName="{1,20}({user}[^"]+)"""",
      """TargetDomainName="{1,20}({domain}[^"]+)"""",
      """TargetSid="{1,20}({user_sid}[^"]+)"""",
      """IpAddress="{1,20}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """Status="{1,20}({result_code}[^"]+)"""",
      """ServiceName="({service_name}[^"]+)""",
      """TicketEncryptionType="({ticket_encryption_type}[^"]+)""",
      """TicketOptions="({ticket_options}[^"]+)""",
    ]
    DupFields = ["host->dest_host"]
  }
```