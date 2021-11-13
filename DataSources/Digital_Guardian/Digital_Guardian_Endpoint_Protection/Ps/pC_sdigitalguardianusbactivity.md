#### Parser Content
```Java
{
Name = s-digitalguardian-usb-activity
  Conditions = [ "Data Egress to Removable", """Block_Code="Not Blocked"""",""" Policy=""" , """ Resolution_Status="""]

splunk-digitalguardian-usb-activity = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "M/dd/yyyy HH:mm:ss a"
  
  Fields = [
    """Agent_Local_Time="({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|AM|pm|PM))""",
    """\WComputer_Name ="([^\\=]{1,2000}(\/)+)?({host}[\w\.-]{1,2000})"""",
    """\WUser_Name ="(({domain}[^\/]{1,2000})\/+)?({user}.+?)"""",
    """\WDestination_Device_ID="({device_id}[^"]{1,2000})"""",
    """\WDestination_Drive_Type="({device_type}[^"]{1,2000})"""",
    """\WOperation="({activity}[^"]{1,2000})"""",
    """\WRule="({rule}[^"]{1,2000})"""",
    """\WPolicy="({policy}[^"]{1,2000})"""",
    """\WRule_Action_Type="({rule_action}[^"]{1,2000})"""",
    """\WBytes_Written="({bytes}\d{1,100})"""",
    """\WComputer_Type="({os}[^"]{1,2000})"""",
    """\WSource_Directory="({file_parent}[^"]{1,2000})"""",
    """\WSource_File="({file_name}[^"]{1,2000})"""",
    """\WApplication="({process_name}[^"]{1,2000})"""",
  ]
    DupFields = [ "host->dest_host" 
}
```