#### Parser Content
```Java
{
Name = win-powershell-command
   Vendor = Microsoft
   Product = Microsoft Windows
   Lms = Direct
   DataType = "process-created"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
   Conditions = [  """>4103</EventID>""",   """CommandInvocation""",       """Script Name ="""    ]
   Fields = [
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """<TimeCreated SystemTime=\'({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)\'\/>""",
      """>({event_code}4103)<\/EventID>""",
      """<Computer>({dest_host}.*?)<\/Computer>""",
      """<Security UserID='({user_sid}[\w-]{1,2000})'""",
      """Script Name =\s{1,100}({process}({directory}([\w:]{1,2000}\\)?([^\\]{1,2000}?\\)*?)({process_name}[^\\]{0,2000}?))\s{1,100}Command Path =""",
      """User = (({domain}[^\\]{1,2000}?)\\)?({user}[^\s]{1,2000})\s{1,100}Connected User =""",
      """CommandInvocation\(.+?\):\s{0,100}"({command_invocation}[^"]{1,2000})""",
      """value="{0,20}(?:function\s)?({command_module}[^\s"]{1,2000})""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({powershell_image}[^\s]{1,2000})\s{1,100}EngineVersion""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({command_line}[^\s]{1,2000})""""
    """CommandInvocation\(.+?\):\s{0,100}\\*"({command_invocation}[^"\\]{1,2000})""",
    """Details:.+?CommandInvocation.+?ParameterBinding.+?value=\\"(function\s)?({command_module}[^\s\\,"]{1,2000})""",
   ]
   DupFields = ["directory->process_directory"]
 

}
```