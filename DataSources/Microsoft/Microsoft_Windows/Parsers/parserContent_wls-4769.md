#### Parser Content
```Java
{
Name = wls-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""LogType="WLS"""", """EventID="4769""""]
    Fields = [
      """Computer="{1,20}({host}[^"]+)"""",
      """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """EventRecordID="{1,20}({record_id}[^"]+)"""",
      """TargetUserName="{1,20}({user}[^@]+)@({domain}[^"]+)"""",
      """TargetLogonId="{1,20}({logon_id}[^"]+)"""",
      """ServiceName="{1,20}({dest_host}[^"]+\$)"""",
      """ServiceName="{1,20}({service_name}[^"]+)"""",
      """IpAddress="{1,20}(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """Status="{1,20}({result_code}[^"]+)"""",
      """TicketEncryptionType="{1,20}({ticket_encryption_type}[^"]+)""""
      """TicketOptions="{1,20}({ticket_options}[^"]+)""""
    ]
  }
```