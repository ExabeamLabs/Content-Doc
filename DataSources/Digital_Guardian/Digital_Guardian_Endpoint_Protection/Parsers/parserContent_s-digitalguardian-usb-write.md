#### Parser Content
```Java
{
Name = s-digitalguardian-usb-write
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""Agent_UTC_Time=""","""Was_Destination_Removable="True"""", """Destination_Drive_Type="Removable"""", """Operation="File Copy"""" ]
  Fields = [
    """Agent_UTC_Time="({time}\d+\/\d+\/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]+)""",
    """Computer_Name="([^\\]+\\)?({src_host}[^"]+)"""",
    """User_Name="(({domain}[^\\]+)\\)?({user}[^"]+)"""",
    """Source_Directory="({src_file_dir}[^"]+)"""",
    """Source_File="({src_file_name}[^"]+)"""",
    """Destination_Directory="({file_parent}[^"]+)"""",
    """Destination_File="({file_name}[^"]+)"""",
    """Destination_File_Extension="({file_ext}[^"]+)"""",
    """Application="({process_name}[^"]+)"""",
    """Operation="({event_code}[^"]+)"""",
    """Bytes_Written="({bytes}[^"]+)"""",
    """Given_Name="({first_name}[^"]+)"""",
    """Surname="({last_name}[^"]+)"""",
    """Email_Address="({user_email}[^@]+@[^.]+\.[^"]+)""""
  ]
}
```