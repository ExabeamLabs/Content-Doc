#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-alert-1
  Conditions = [ """Rule_Violation="True"""", """Block_Code="Rule Block"""" ]
  Fields = ${DGParserTemplates.splunk-digitalguardian-dlp-alert.Fields}[
    """[^_]Custom_String_4="({alert_name}[^"]+)""",
    """[^_]Block_Code="({alert_type}[^"]+)""",
    """[^_]Bytes_Read="(?:|({bytes}[^"]+))"""",
  ]
}
splunk-digitalguardian-dlp-alert = {
  Vendor = Digital Guardian
  Product = Network DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """[^_](Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d+\/\d+\/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]+?@\s*)?({host}[^\s]+)""",
    """[^_]Computer_Name="([^\/\\"]+[\/\\]+)?({host}[^"]+)"""",
    """[^_]User_Name="(?:|(({domain}[^"\/\\]+)[\/\\]+)?({user}[^"]+))"""",
    """[^_]Domain_Name="(?:|({domain}[^"]+))"""",
    """[^_]Rule="({alert_name}[^"]+)""",
    """[^_]Operation="({alert_type}[^"]+)""",
    """[^_]Protocol="({protocol}[^"]+)""",
    """[^_]Severity="({alert_severity}[^"]+)"""",
    """[^_]Destination_Device_ID="({device_id}[^"]+)"""",
    """[^_]Source_File="(?:|({file_name}[^"]+))"""",
    """[^_]Destination_File="(?:|({file_name}[^"]+))"""",
    """[^_]Bytes_Written="(?:|({bytes}\d+))"""",
    """[^_]IP_Address="(?:|({dest_ip}[^"]+))"""",
    """[^_]Application="(?:|({process}[^"]+))"""",
    """[^_]Email_Recipient="(?:|({target}[^"]+))"""",
    """[^_]Computer_Type="(?:|({os}[^"]+))""""
  ]

```