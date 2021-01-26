#### Parser Content
```Java
{
Name = symantec-usb-block
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ ",Blocked,", ",Begin:", ",Action Type:", ",Device ID:" ]
    Fields = [ """exabeam_host=({host}[^,\s]+)""",
      """SymantecServer:\s*({host}[\w\-.]+)""",
      """exabeam_raw=\d+-\d+-\d+\s+\d+:\d+:\d+,({alert_severity}[^,]*),""",
      """(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s,]+)),Blocked,""",
      """Begin:\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({alert_name}Blocked)"""
      """Rule:\s+(?:|({alert_name}[^,]+)),""",
      """({alert_type}Blocked)"""
      """Rule: [^,]*,\d+,({target}[^,]+),\d+,[^,]*,"?({file_name}.+?)"?,User""",
      """Rule: [^,]*,\d+,({process}.*(\/|\\)({process_name}[^\/\\]+)),\d,""",
      """\| \[[^,]*,\d+,[^,]+,\d+,[^,]+,.*/({file_name}.+?)"?,User""",
      """User:\s+(SYSTEM|({user}[^\s]+?)),Domain""",
      """User Name:\s*(SYSTEM|({user}[^\s,]+))""",
      """Domain:\s+({domain}.+?),Action Type""",
      """File size \(({bytes_unit}.+?)\):\s*({bytes_num}\d+)""",
      """Device ID:\s+({device_id}.+)&\d+""",
      """({outcome}Blocked)""",
      """File size \(({bytes_unit}[^\)]+)"""
    ]
    DupFields = ["user->sender"]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "src_host->dlpDeviceName", "file_name->dlpFileName", "alert_type->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```