#### Parser Content
```Java
{
Name = darktrace-app-login
 Product = Darktrace
 Vendor = Darktrace
 Lms = Direct
 DataType = "app-login"
 TimeFormat ="yyyy-MM-dd HH:mm:ss"
 Conditions =[ """endpoint":"/login""", """description":"""", """Successful login""", """method":"POST""" ]
 Fields =[
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]+)""",
   """"+username"+:"+({user}[^"]+)""",
   """"+endpoint"+:"+\/*({activity}[^"]+)""",
   """"+method"+:"+({method}[^"]+)""",
   """"+ip"+:"+\/*({src_ip}[^"]+)""",
   """"+status"+:({result_code}\d+)""",
   """"+description"+:"+({additional_info}[^"]+)"""
   ]
}

{
 Name = darktrace-failed-app-login
 Product = Darktrace
 Vendor = Darktrace
 Lms = Direct
 DataType = "failed-app-login"
 TimeFormat ="yyyy-MM-dd HH:mm:ss"
 Conditions =[ """endpoint":"/login""", """description":"""", """Failed login""", """method":"POST""" ]
 Fields =[
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]+)""",
   """"+username"+:"+({user}[^"]+)""",
   """"+endpoint"+:"+\/*({activity}[^"]+)""",
   """"+method"+:"+({method}[^"]+)"""
   """"+ip"+:"+\/*({src_ip}[^"]+)""",
   """"+status"+:({result_code}\d+)""",
   """"+description"+:"+({additional_info}[^"]+)"""
   ]
}

{
 Name = netdoc-app-activity-1
 Product = Netdocs
 Vendor = Netdocs
 Lms = Splunk
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 DataType = "app-activity"
 Conditions = [ """netdocs""", """memberType": """, """storageObject":""", """cabinet": """ ]
 Fields =[
   """"+host"+:\s"+({host}[^"]+)"+,""",
   """date"+:\s"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
   """"+date"+:\s+"+({time}[^"]+)"+""",
   """"+user.+?"+name"+:\s+"+({user_fullname}[^"]+)"+\}?,""",
   """"+memberType.+?"+id"+:\s+"+({user_id}[^"]+)""",
   """"+fileExtension"+:\s+"+({file_extension}[^"]+)""",
   """"+size"+:\s+"+({bytes}[^"]+)""",
   """"+memberType"+:\s+"+({object}[^"]+)""",
   """"+cabinet".+?id"+:\s+"+({dest_host}[^"]+)""",
   """"+name"+: "+({activity}[^"]+)"+}}"*""",
   """name"+:\s+"+({activity}[^"]+)"+,\s+"+(date|source|storageObject|host)""",
   """activity"+:\s+\{"+name"+:\s+"+({activity}[^"]+)""",
   """"+CorpMatter"+:\s+"+({corp_matter}[^"]+)"+""",
   """"+CorpClient"+:\s+"+({corp_client}[^"]+)"+""",
   """"+cabinet"+:.+?name"+:\s"+({cabinet_name}[^"]+)""",
   """name"+:\s+"+({file_name}[^"]+)"+,?\s+"+(TypeofEngagement|DocumentType|OfficeofAuthor)"""
   """"+docId"+:\s+"+({doc_id}[^"]+)"""
   """activity"+:\s+\{"+name"+:\s+"+({activity}[^"]+)""",
   """"access"+:\s+"+({additional_info}[^"]+)"""
   """name"+:\s+"+({file_name}[^"]+)"+,\s+"+(TypeofEngagement|DocumentType|OfficeofAuthor|Author|fileExtension|size)""",
   """name"+:\s+"+({file_name}[^"]+)"+}?,\s+"+(user|CorpClient|version|Client)""",
   """(docId|Author|DocumentType)"+:\s+"+[^"]+"+,\s+"+name"+:\s+"+({file_name}[^"]+)""",
   """({app}netdocs)""",
    ]
   DupFields = [ "host->src_ip", "activity->accesses" ]
}


${HashiCorpParserTemplates.hashicorp-login-activity}{
  Name = hashicorp-password-reset
  DataType = "account-password-reset"
  Conditions = [ """"type":"request"""", """"auth":{""", """"operation":"create"""", """"token_type"""", """"ttam_service":"vault"""" ]
  Fields = ${HashiCorpParserTemplates.hashicorp-login-activity.Fields} []
}
```