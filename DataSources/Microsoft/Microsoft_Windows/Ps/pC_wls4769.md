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
      """Computer="{1,20}({host}[^"]{1,2000})"""",
      """"({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
      """TargetUserName ="{1,20}({user}[^@]{1,2000})@({domain}[^"]{1,2000})"""",
      """TargetLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
      """ServiceName ="{1,20}({dest_host}[^"]{1,2000}\$)"""",
      """ServiceName ="{1,20}({service_name}[^"]{1,2000})"""",
      """IpAddress="{1,20}(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})""",
      """Status="{1,20}({result_code}[^"]{1,2000})"""",
      """TicketEncryptionType="{1,20}({ticket_encryption_type}[^"]{1,2000})""""
      """TicketOptions="{1,20}({ticket_options}[^"]{1,2000})""""
    ]
  

}
```