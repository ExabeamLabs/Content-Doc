#### Parser Content
```Java
{
Name = s-mcafee-usb-insert-cddrive
  Conditions = [ """DeviceClassName ="DVD/CD-ROM drives""", """InsertionTime="""", """destination="""", """RulesToDisplay="""" ]

splunk-mcafee-usb-insert-activity = {
      Vendor = McAfee
      Product = McAfee Endpoint Security
      Lms = Splunk
      DataType = "usb-activity"
      TimeFormat = "yyyy-MM-dd HH:mm:ss"
      Fields = [
        """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
        """InsertionTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """RulesToDisplay="({activity}[^"]{1,200})""",
        """IP="({dest_ip}[A-Fa-f.\d:]{1,200})""",
        """\sName ="({dest_host}[^"]{1,200})""",
        """Username_NTLM="((({domain}[^\\]{1,200})\\)?({user}[^"]{1,200}))""",
        """USBVendorId="(\s{0,100}|({device_id}[^"]{1,200}))"""",
        """DeviceName ="({device_type}[^"]{1,200})""",
        """\sFileName ="({file_name}[^"]{1,2000})""",
        """({action}Block)""",
        """TotalContentSize="({bytes}\d{1,200})""" 

      ]
      DupFields = ["activity->activity_details"]
    }
  
}

McAfeeParsers = [

############
# Exabeam Lms McAfee Parsers
############
  {
    Name = s-mcafee-cleaned-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "M/d/yyyy\tH:mm:ss a"
    Conditions = [ " (MD5)", "\tCleaned"]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]{1,2000})""",  
      """({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM)+)\t({additional_info}[^\t]{1,2000}?)\s{0,100}\t(({domain}[^\t]{1,2000})(\\)+)?({user}[^\t]{1,2000})\t({process}[^\t]{1,2000})\t({malware_url}.+?\\({malware_file_name}[^\\]{1,2000}))\t({alert_name}[^\t]{1,2000}?)\s{0,100}\(({alert_type}[^\)]{1,2000})\)\t({md5}\S+?)\s{0,100}\(MD5\)"""
    ]
    DupFields=[ "host->src_host" ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_host->host_name"]},
        {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]},
        {EntityType="file", Name ="file_name", Fields=["malware_file_name->file_name"]}
      ]
    }
  }, 
 
  {
    Name = s-mcafee-clean-failed-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "M/d/yyyy\tH:mm:ss a"
    Conditions = [ " (MD5)", " (Clean failed)"]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]{1,2000})""",  
      """({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM)+)\t({additional_info}[^\t]{1,2000}?)\s{0,100}\t(({domain}[^\t]{1,2000})(\\)+)?({user}[^\t]{1,2000})\t(\w+\[({process_id}\d{1,100})\]|({process}[^\t]{1,2000}))\t({malware_url}.+?\\({malware_file_name}[^\\]{1,2000}))\t({alert_name}[^\t]{1,2000}?)\s{0,100}\(({alert_type}[^\)]{1,2000})\)\t({md5}\S+?)\s{0,100}\(MD5\)"""
    ]
    DupFields=[ "host->src_host" ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_host->host_name"]},
        {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]},
        {EntityType="file", Name ="file_name", Fields=["malware_file_name->file_name"]}
      ]
    }
  },
 
  {
    Name = s-mcafee-deleted-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "M/d/yyyy\tH:mm:ss a"
    Conditions = [" (MD5)", "\tDeleted"]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]{1,2000})""",  
      """({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM)+)\t({additional_info}[^\t]{1,2000}?)\s{0,100}\t(({domain}[^\t]{1,2000})(\\)+)?({user}[^\t]{1,2000})\t({process}[^\t]{1,2000})\t({malware_url}.+?\\({malware_file_name}[^\\]{1,2000}))\t({alert_name}[^\t]{1,2000}?)\s{0,100}\(({alert_type}[^\)]{1,2000})\)\t({md5}\S+?)\s{0,100}\(MD5\)"""
    ]
    DupFields=[ "host->src_host" ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_host->host_name"]},
        {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]},
        {EntityType="file", Name ="file_name", Fields=["malware_file_name->file_name"]}
      ]
    }
  }, 
 
    {
      Name = cef-mcafee-print-activity
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "print-activity"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|DLP: Printing Protection|""" ]
      Fields = [
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\sCEF:""",
        """(\s|\|)cs2=({dest_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs2=\\{1,25}.{1,2000}?(\\{1,25}({printer_name}.{1,2000}?))\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)duser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fname=({object}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)({activity}Printing)""",
      ]
    },
 
    {
      Name = cef-mcafee-print-activity-1
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|dlp """, """cs2Label=Printer Name""" ]
      Fields = [
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs2=({printer_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fname=({object}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s{1,100}([\w\.-]{1,2000}=|$)"""
      ]
    },

  {
    Name = iguard-dlp-alert
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = ["CEF:", "|McAfee|iGuard"]
    Fields = [ """\send=({time}\w{3} \d{1,100} \d{1,100} \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d ({host}[^\s]{1,2000})""",
      """CEF([^\|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
      """CEF([^\|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
      """cs1=({alert_type}.+?)\s{1,100}cs1Label""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """fsize=({bytes}\d{1,100})""",
      """app=({protocol}.+?)\s{1,100}\w+=""",
      """app=SMTP.+?suser=({sender}[^\s]{1,2000})""",
      """app=SMTP.+?duser=({recipients}.*?)\s{1,100}\w+=""",
      """app=SMTP.+?duser=({external_address}[^\s,]{1,2000})""",
      """app=SMTP.+?cs2="{0,20}({subject}[^"]{0,2000})""",
      """app=SMTP.+?fname=(?:Unknown|({attachment}.+?))\s{1,100}$""",
      """app=HTTP.+?fname=({target}.+?)\s{1,100}$""",
    
}
```