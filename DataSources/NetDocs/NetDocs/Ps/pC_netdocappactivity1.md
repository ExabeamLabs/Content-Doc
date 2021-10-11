#### Parser Content
```Java
{
Name = netdoc-app-activity-1
 Product = NetDocs
 Vendor = NetDocs
 Lms = Splunk
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 DataType = "app-activity"
 Conditions = [ """netdocs""", """memberType": """, """storageObject":""", """cabinet": """ ]
 Fields =[
   """"{1,20}host"{1,20}:\s"{1,20}({host}[^"]{1,2000})"{1,20},""",
   """date"{1,20}:\s"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
   """"{1,20}date"{1,20}:\s{1,100}"{1,20}({time}[^"]{1,2000})"{1,20}""",
   """"{1,20}user.+?"{1,20}name"{1,20}:\s{1,100}"{1,20}({user_fullname}[^"]{1,2000})"{1,20}\}?,""",
   """"{1,20}memberType.+?"{1,20}id"{1,20}:\s{1,100}"{1,20}({user_id}[^"]{1,2000})""",
   """"{1,20}fileExtension"{1,20}:\s{1,100}"{1,20}({file_extension}[^"]{1,2000})""",
   """"{1,20}size"{1,20}:\s{1,100}"{1,20}({bytes}[^"]{1,2000})""",
   """"{1,20}memberType"{1,20}:\s{1,100}"{1,20}({object}[^"]{1,2000})""",
   """"{1,20}cabinet".+?id"{1,20}:\s{1,100}"{1,20}({dest_host}[^"]{1,2000})""",
   """"{1,20}name"{1,20}: "{1,20}({activity}[^"]{1,2000})"{1,20}}}"{0,20}""",
   """name"{1,20}:\s{1,100}"{1,20}({activity}[^"]{1,2000})"{1,20},\s{1,100}"{1,20}(date|source|storageObject|host)""",
   """activity"{1,20}:\s{1,100}\{"{1,20}name"{1,20}:\s{1,100}"{1,20}({activity}[^"]{1,2000})""",
   """"{1,20}CorpMatter"{1,20}:\s{1,100}"{1,20}({corp_matter}[^"]{1,2000})"{1,20}""",
   """"{1,20}CorpClient"{1,20}:\s{1,100}"{1,20}({corp_client}[^"]{1,2000})"{1,20}""",
   """"{1,20}cabinet"{1,20}:.+?name"{1,20}:\s"{1,20}({cabinet_name}[^"]{1,2000})""",
   """name"{1,20}:\s{1,100}"{1,20}({file_name}[^"]{1,2000})"{1,20},?\s{1,100}"{1,20}(TypeofEngagement|DocumentType|OfficeofAuthor)"""
   """"{1,20}docId"{1,20}:\s{1,100}"{1,20}({doc_id}[^"]{1,2000})"""
   """activity"{1,20}:\s{1,100}\{"{1,20}name"{1,20}:\s{1,100}"{1,20}({activity}[^"]{1,2000})""",
   """"access"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]{1,2000})"""
   """name"{1,20}:\s{1,100}"{1,20}({file_name}[^"]{1,2000})"{1,20},\s{1,100}"{1,20}(TypeofEngagement|DocumentType|OfficeofAuthor|Author|fileExtension|size)""",
   """name"{1,20}:\s{1,100}"{1,20}({file_name}[^"]{1,2000})"{1,20}}?,\s{1,100}"{1,20}(user|CorpClient|version|Client)""",
   """(docId|Author|DocumentType)"{1,20}:\s{1,100}"{1,20}[^"]{1,2000}"{1,20},\s{1,100}"{1,20}name"{1,20}:\s{1,100}"{1,20}({file_name}[^"]{1,2000})""",
   """({app}netdocs)""",
    ]
   DupFields = [ "host->src_ip", "activity->accesses" ]
}
```