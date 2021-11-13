#### Parser Content
```Java
{
Name = s-digitalguardian-usb-insert-2
  Conditions = [ """Operation="Device Added"""" , """Agent_UTC_Time=""" ]

splunk-digitalguardian-usb-insert = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """(\s|exabeam_\w+=)(Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\s|exabeam_\w+=)Computer_Name ="([^\/"]{1,2000}\/)?({host}[^"]{1,2000})"""",
    """(\s|exabeam_\w+=)User_Name ="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Domain_Name ="(?:|({domain}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)User_Name ="(?:|([^"\/]{1,2000}\/+)?({user}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Device_ID="(?:|({device_id}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Drive_Type="(?:|({device_type}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Friendly_Name ="(?:|({activity_details}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Operation="(?:|({event_code}[^"]{1,2000}))"""",
  ]
    DupFields = [ "host->dest_host" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "activity_details->description"]
    NameTemplate = """Digital Guardian ${device_type} insert found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_host->host_name"]},
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]}
    
}
```