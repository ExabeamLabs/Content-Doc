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
    """Agent_UTC_Time="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """Computer_Name="([^\\]{1,2000}\\)?({src_host}[^"]{1,2000})"""",
    """User_Name="(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """Source_Directory="({src_file_dir}[^"]{1,2000})"""",
    """Source_File="({src_file_name}[^"]{1,2000})"""",
    """Destination_Directory="({file_parent}[^"]{1,2000})"""",
    """Destination_File="({file_name}[^"]{1,2000})"""",
    """Destination_File_Extension="({file_ext}[^"]{1,2000})"""",
    """Application="({process_name}[^"]{1,2000})"""",
    """Operation="({event_code}[^"]{1,2000})"""",
    """Bytes_Written="({bytes}[^"]{1,2000})"""",
    """Given_Name="({first_name}[^"]{1,2000})"""",
    """Surname="({last_name}[^"]{1,2000})"""",
    """Email_Address="({user_email}[^@]{1,2000}@[^.]{1,2000}\.[^"]{1,2000})""""
  ]
}
```