#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-alert-2
  Conditions = [ """ Policy=""" , """ Resolution_Status=""" ]

splunk-digitalguardian-dlp-alert = {
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """[^_](Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """[^_]Computer_Name ="([^\/\\"]{1,2000}[\/\\]{1,2000})?({host}[^"]{1,2000})"""",
    """[^_]User_Name ="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """[^_]Domain_Name ="(?:|({domain}[^"]{1,2000}))"""",
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
  DupFields = [ "host->src_host" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "protocol->dlpProtocol", "src_host->dlpDeviceName", "file_name->dlpFileName", "bytes->dlpFileSize"]
    NameTemplate = """Digital Guardian DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_host->host_name"]},
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address"]},
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]}
    
}
```