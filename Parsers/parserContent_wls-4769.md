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
      """Computer="+({host}[^"]+)"""",
      """"({time}\d\d\d\d\-\d+\-\d+T\d\d:\d\d:\d\d)""",
      """EventID="+({event_code}[^"]+)"""",
      """EventRecordID="+({record_id}[^"]+)"""",
      """TargetUserName="+({user}[^@]+)@({domain}[^"]+)"""",
      """TargetLogonId="+({logon_id}[^"]+)"""",
      """ServiceName="+({dest_host}[^"]+\$)"""",
      """ServiceName="+({service_name}[^"]+)"""",
      """IpAddress="+(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",
      """Status="+({result_code}[^"]+)"""",
      """TicketEncryptionType="+({ticket_encryption_type}[^"]+)""""
      """TicketOptions="+({ticket_options}[^"]+)""""
    ]
  }
```