#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-alert-1
  Conditions = [ """Rule_Violation="True"""", """Block_Code="Rule Block"""" ]
  Fields = ${DGParserTemplates.splunk-digitalguardian-dlp-alert.Fields}[
    """[^_]Custom_String_4="({alert_name}[^"]{1,2000})""",
    """[^_]Block_Code="({alert_type}[^"]{1,2000})""",
    """[^_]Bytes_Read="(?:|({bytes}[^"]{1,2000}))"""",
  ]
}
splunk-digitalguardian-dlp-alert = {
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """[^_](Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """[^_]Computer_Name="([^\/\\"]{1,2000}[\/\\]{1,2000})?({host}[^"]{1,2000})"""",
    """[^_]User_Name="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """[^_]Domain_Name="(?:|({domain}[^"]{1,2000}))"""",
    """[^_]Rule="({alert_name}[^"]{1,2000})""",
    """[^_]Operation="({alert_type}[^"]{1,2000})""",
    """[^_]Protocol="({protocol}[^"]{1,2000})""",
    """[^_]Severity="({alert_severity}[^"]{1,2000})"""",
    """[^_]Destination_Device_ID="({device_id}[^"]{1,2000})"""",
    """[^_]Source_File="(?:|({file_name}[^"]{1,2000}))"""",
    """[^_]Destination_File="(?:|({file_name}[^"]{1,2000}))"""",
    """[^_]Bytes_Written="(?:|({bytes}\d{1,100}))"""",
    """[^_]IP_Address="(?:|({dest_ip}[^"]{1,2000}))"""",
    """[^_]Application="(?:|({process}[^"]{1,2000}))"""",
    """[^_]Email_Recipient="(?:|({target}[^"]{1,2000}))"""",
    """[^_]Computer_Type="(?:|({os}[^"]{1,2000}))""""
  ]

```