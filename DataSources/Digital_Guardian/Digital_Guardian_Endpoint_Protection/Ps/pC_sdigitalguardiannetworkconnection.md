#### Parser Content
```Java
{
Name = s-digitalguardian-network-connection
  Conditions = [ """Operation_ID="4"""" , """Agent_UTC_Time=""" ]
}
splunk-digitalguardian-network-connection ={
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Splunk
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """(\s|exabeam_\w+=)?(Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\s|exabeam_\w+=)Computer_Name ="([^\/"]{1,2000}\/)?({host}[^"]{1,2000})"""",
    """(\s|exabeam_\w+=)User_Name ="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Domain_Name ="(?:|({domain}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Source_Directory="(?:|({src_file_dir}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Source_File="(?:|({src_file_name}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Destination_Directory="(?:|({file_parent}.+?))\\?"""",
    """(\s|exabeam_\w+=)Destination_File="(?:|({file_name}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Destination_File_Extension="(?:|({file_ext}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Application="(?:|({process_name}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)IP_Address="(?:|({dest_ip}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Product_Name ="(?:|({app}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Bytes_Written="(?:|({bytes}\d{1,100}))"""",
    """(\s|exabeam_\w+=)Operation((_ID)?)=""(?:|({event_code}[^"]{1,2000}))"""",
    """Remote_Port="({dest_port}[^"]{1,2000})"""",
    """Local_Port="(?:|({src_port}[^"]{1,2000}))"""",
    """Source_IP_Address="(?:|({src_ip}[^"]{1,2000}))"""",
    """Was_Blocked="(?:|({outcome}[^"]{1,2000}))"""",
     """Operation_ID="({event_code}[^"]{1,2000})""""
  ]
  DupFields = [ "host->dest_host" ]}
```