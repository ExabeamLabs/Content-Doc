#### Parser Content
```Java
{
Name = code42-file-operations-4
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType"""", """"osHostName"""]
  Fields = [ 
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventType"{1,20}:\s{0,100}"{1,20}({accesses}MODIFIED|DELETED|READ|CREATED)""",
    """"mimeTypeByExtension"{1,20}:\s{0,100}"{1,20}({mime}[^"]{1,2000})"""",
    """"tabUrl"{1,20}:\s{0,100}"{1,20}({full_url}[^"]{1,2000})"""",
    """"exposure"{1,20}:\s{0,100}\["{0,20}({log_source}[^"\]]{1,2000})"{0,20}\]""",
    """"processName"{1,20}:\s{0,100}"{1,20}({process_name}[^"]{1,2000})"""",
    """"userUid"{1,20}:\s{0,100}"{1,20}({user_uid}[^"]{1,2000})"""",
    """"deviceUid"{1,20}:\s{0,100}"{1,20}({device_id}[^"]{1,2000})"""",
    """"publicIpAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})"""",
    """"domainName"{1,20}:\s{0,100}"{1,20}({domain}[^"]{1,2000})"""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})"""",
    """"filePath"{1,20}:\s{0,100}"{1,20}({file_path}[^"]{1,2000})"""",
    """"fileName"{1,20}:\s{0,100}"{1,20}({file_name}[^"]{1,2000})"""",
    """"fileCategory"{1,20}:\s{0,100}"{1,20}({file_type}[^"]{1,2000})"""",
    """"fileCategoryByExtension"{1,20}:\s{0,100}"{1,20}({file_ext}[^"]{1,2000})"""",
    """"fileSize"{1,20}:\s{0,100}({file_size}\d{1,100})""",
    """"processOwner"{1,20}:\s{0,100}"{1,20}({user}[^"]{1,2000})"""",
    """"md5Checksum"{1,20}:\s{0,100}"{1,20}({md5}[^"]{1,2000})"""",
    """"sha256Checksum"{1,20}:\s{0,100}"{1,20}({sha256}[^"]{1,2000})"""",
    """"deviceUserName"{1,20}:\s{0,100}"{1,20}({user_email}[^"]{1,2000})"""",
    """"osHostName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})"""",
    """"windowTitle"{1,20}:\s{0,100}\["{0,20}({service}[^"\]]{1,2000})"{0,20}\]""",
    """"actor"{1,20}:"{1,20}(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))""",
  ]
  DupFields = ["file_path->file_parent", "dest_host->device_name"]
}
```