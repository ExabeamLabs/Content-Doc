#### Parser Content
```Java
{
Name = cef-liebsoft-app-activity-2
  Conditions = [ """CEF:""", """|Liebsoft|""", """|EVENT_ID_JOB_ACCOUNT_ELEVATED|""" ]
}

${LiebsoftParserTemplates.cef-liebsoft-app-activity}{
  Name = cef-liebsoft-app-activity-3
  Conditions = [ """CEF:""", """|Liebsoft|""", """|EVENT_ID_JOB_ACCOUNT_ELEVATION_DEELEVATED|""" ]
}

${LiebsoftParserTemplates.cef-liebsoft-app-activity}{
  Name = cef-liebsoft-app-activity-4
  Conditions = [ """CEF:""", """|Liebsoft|""", """|EVENT_ID_JOB_ACCOUNT_ELEVATION_DEELEVATION_FAILED|""" ]
}

${LiebsoftParserTemplates.cef-liebsoft-app-activity}{
  Name = cef-liebsoft-app-activity-5
  Conditions = [ """CEF:""", """|Liebsoft|""", """|EVENT_ID_SHARED_CREDENTIAL_LIST_ADDED_ACCOUNT|""" ]
}

 {
   Name = s-net2door-badge-access
   Vendor = Paxton
   Product = NET2DOOR
   Lms = Splunk
   DataType = "physical-access"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Conditions = [""""eventtypedescription"""", """"eventid"""", """"peripheralname""""]
   Fields = [
     """exabeam_host=([^=]*@\s*)?({host}[^\s]+)""",
     """"eventtime"*:"*({time}[^"]+)"*(,|$)""",
     """"peripheralname"*:"*({location_city}.+?)\s*\-\s*({location_building}.+?)\s*(\(|\-|")""",
     """"peripheralname"*:"*([^\-]+)\-([^\-]+)\-\s*(\s*|({location_door}.+?))(\s*\-)?\s*(IN|OUT)""",
     """"eventtypedescription"*:"*({outcome}[^",]+)"*(,|$)""",
     """"eventtypedescription"*:"*([^\-]+\-\s*({outcome_reason}[^",]+))"*(,|$)""",
     """"username"*:"*(?:({last_name}[^,]+),\s*({first_name}[^",]+))"*(,|$)""",
     """"cardnumber"*:"*({badge_id}\d+)""",
     """"userid"*:"*({employee_id}[^",]+)"*(,|$)""",
     """\(({direction}[^\)]+)\)"""
   ]
 }
```