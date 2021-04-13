import json
import os

# AWS Managed Rules from "Core Rule Set"
NoUserAgent_HEADER, NoUserAgent_HEADER_lst = "NoUserAgent_HEADER", []
UserAgent_BadBots_HEADER, UserAgent_BadBots_HEADER_lst = "UserAgent_BadBots_HEADER", []
SizeRestrictions_QUERYSTRING, SizeRestrictions_QUERYSTRING_lst = "SizeRestrictions_QUERYSTRING", []
SizeRestrictions_Cookie_HEADER, SizeRestrictions_Cookie_HEADER_lst = "SizeRestrictions_Cookie_HEADER", []
SizeRestrictions_BODY, SizeRestrictions_BODY_lst = "SizeRestrictions_BODY", []
SizeRestrictions_URIPATH, SizeRestrictions_URIPATH_lst = "SizeRestrictions_URIPATH", []
EC2MetaDataSSRF_BODY, EC2MetaDataSSRF_BODY_lst = "EC2MetaDataSSRF_BODY", []
EC2MetaDataSSRF_COOKIE, EC2MetaDataSSRF_COOKIE_lst = "EC2MetaDataSSRF_COOKIE", []
EC2MetaDataSSRF_QUERYARGUMENTS, EC2MetaDataSSRF_QUERYARGUMENTS_lst = "EC2MetaDataSSRF_QUERYARGUMENTS", []
EC2MetaDataSSRF_URIPATH, EC2MetaDataSSRF_URIPATH_lst = "EC2MetaDataSSRF_URIPATH", []
GenericLFI_BODY, GenericLFI_BODY_lst = "GenericLFI_BODY", []
GenericLFI_QUERYARGUMENTS, GenericLFI_QUERYARGUMENTS_lst = "GenericLFI_QUERYARGUMENTS", []
GenericLFI_URIPATH, GenericLFI_URIPATH_lst = "GenericLFI_URIPATH", []
RestrictedExtensions_URIPATH, RestrictedExtensions_URIPATH_lst = "RestrictedExtensions_URIPATH", []
RestrictedExtensions_QUERYARGUMENTS, RestrictedExtensions_QUERYARGUMENTS_lst = "RestrictedExtensions_QUERYARGUMENTS", []
GenericRFI_BODY, GenericRFI_BODY_lst   = "GenericRFI_BODY", []
GenericRFI_QUERYARGUMENTS, GenericRFI_QUERYARGUMENTS_lst = "GenericRFI_QUERYARGUMENTS", []
GenericRFI_URIPATH, GenericRFI_URIPATH_lst = "GenericRFI_URIPATH", []
CrossSiteScripting_COOKIE, CrossSiteScripting_COOKIE_lst  = "CrossSiteScripting_COOKIE", []
CrossSiteScripting_URIPATH, CrossSiteScripting_URIPATH_lst = "CrossSiteScripting_URIPATH", []
CrossSiteScripting_QUERYARGUMENTS, CrossSiteScripting_QUERYARGUMENTS_lst = "CrossSiteScripting_QUERYARGUMENTS", []
CrossSiteScripting_BODY, CrossSiteScripting_BODY_lst = "CrossSiteScripting_BODY", []

#Defaul_Action of the WebACL
Default_Action, Default_Action_lst = "Default_Action", []

#Customized Rule for selective IP blocking
Block_CN_Rule, Block_CN_Rule_lst = "Block-CN-Rule", []

results = {"NoUserAgent_HEADER" : 0, "UserAgent_BadBots_HEADER" : 0, "SizeRestrictions_QUERYSTRING" : 0, 
    "SizeRestrictions_Cookie_HEADER" : 0, "SizeRestrictions_BODY" : 0, "SizeRestrictions_URIPATH" : 0,
    "EC2MetaDataSSRF_BODY" : 0, "EC2MetaDataSSRF_COOKIE" : 0, "EC2MetaDataSSRF_QUERYARGUMENTS" : 0, 
    "EC2MetaDataSSRF_URIPATH" : 0, "GenericLFI_BODY" : 0, "GenericLFI_QUERYARGUMENTS": 0, "GenericLFI_URIPATH" : 0,
    "RestrictedExtensions_URIPATH" : 0, "RestrictedExtensions_QUERYARGUMENTS" : 0, "GenericRFI_BODY" : 0, 
    "GenericRFI_QUERYARGUMENTS" : 0, "GenericRFI_URIPATH" : 0, "CrossSiteScripting_COOKIE" : 0,
    "CrossSiteScripting_URIPATH" : 0, "CrossSiteScripting_QUERYARGUMENTS" : 0, "CrossSiteScripting_BODY" : 0, 
    "Default_Action" : 0, "Block-CN-Rule" : 0, "Total" : 0}

def appendLog(terminatingRule, log):
    #function that appends the current log in the correct list of logs

    if terminatingRule == "Default_Action":
        Default_Action_lst.append(log)
    elif terminatingRule == "GenericRFI_BODY":
        GenericRFI_BODY_lst.append(log)
    elif terminatingRule == NoUserAgent_HEADER : 
        NoUserAgent_HEADER_lst.append(log)
    elif terminatingRule == "UserAgent_BadBots_HEADER":
        UserAgent_BadBots_HEADER_lst.append(log)
    elif terminatingRule == "SizeRestrictions_QUERYSTRING":
        SizeRestrictions_QUERYSTRING_lst.append(log)
    elif terminatingRule == "SizeRestrictions_Cookie_HEADER":
        SizeRestrictions_Cookie_HEADER_lst.append(log)
    elif terminatingRule == "SizeRestrictions_BODY":
        SizeRestrictions_BODY_lst.append(log)
    elif terminatingRule == "SizeRestrictions_URIPATH":
        SizeRestrictions_URIPATH_lst.append(log)
    elif terminatingRule == "EC2MetaDataSSRF_BODY":
        EC2MetaDataSSRF_BODY_lst.append(log)
    elif terminatingRule == "EC2MetaDataSSRF_COOKIE":
        EC2MetaDataSSRF_COOKIE_lst.append(log)
    elif terminatingRule == "EC2MetaDataSSRF_QUERYARGUMENTS":
        EC2MetaDataSSRF_QUERYARGUMENTS_lst.append(log)
    elif terminatingRule == "EC2MetaDataSSRF_URIPATH":
        EC2MetaDataSSRF_URIPATH_lst.append(log)
    elif terminatingRule == "GenericLFI_BODY":
        GenericLFI_BODY_lst.append(log)
    elif terminatingRule == "GenericLFI_QUERYARGUMENTS":
        GenericLFI_QUERYARGUMENTS_lst.append(log)
    elif terminatingRule == "GenericLFI_URIPATH":
        GenericLFI_URIPATH_lst.append(log)
    elif terminatingRule == "RestrictedExtensions_URIPATH":
        RestrictedExtensions_URIPATH_lst.append(log)
    elif terminatingRule == "RestrictedExtensions_QUERYARGUMENTS":
        RestrictedExtensions_QUERYARGUMENTS_lst.append(log)
    elif terminatingRule == "GenericRFI_QUERYARGUMENTS":
        GenericRFI_QUERYARGUMENTS_lst.append(log)
    elif terminatingRule == "GenericRFI_URIPATH":
        GenericRFI_URIPATH_lst.append(log)
    elif terminatingRule == "CrossSiteScripting_COOKIE":
        CrossSiteScripting_COOKIE_lst.append(log)
    elif terminatingRule == "CrossSiteScripting_URIPATH":
        CrossSiteScripting_URIPATH_lst.append(log)
    elif terminatingRule == "CrossSiteScripting_QUERYARGUMENTS":
        CrossSiteScripting_QUERYARGUMENTS_lst.append(log)
    elif terminatingRule == "CrossSiteScripting_BODY":
        CrossSiteScripting_BODY_lst.append(log)
    elif terminatingRule == "Block-CN-Rule":
        Block_CN_Rule_lst.append(log)

def writeToRuleFile( directory):

    if NoUserAgent_HEADER_lst:
        with open(name_subdir +"/NoUserAgent_HEADER", "w") as out:
            json.dump(NoUserAgent_HEADER_lst, out)
            results[NoUserAgent_HEADER] = len(NoUserAgent_HEADER_lst)
    if UserAgent_BadBots_HEADER_lst:
        with open(name_subdir +"/UserAgent_BadBots_HEADER", "w") as out:
            json.dump(UserAgent_BadBots_HEADER_lst, out)
            results[UserAgent_BadBots_HEADER] = len(UserAgent_BadBots_HEADER_lst)
    if SizeRestrictions_QUERYSTRING_lst:
        with open(name_subdir +"/SizeRestrictions_QUERYSTRING", "w") as out:
            json.dump(SizeRestrictions_QUERYSTRING_lst, out)
            results[SizeRestrictions_QUERYSTRING] = len(SizeRestrictions_QUERYSTRING_lst)           
    if SizeRestrictions_Cookie_HEADER_lst:
        with open(name_subdir +"/SizeRestrictions_Cookie_HEADER", "w") as out:
            json.dump(SizeRestrictions_Cookie_HEADER_lst, out)
            results[SizeRestrictions_Cookie_HEADER] = len(SizeRestrictions_Cookie_HEADER_lst)
    if SizeRestrictions_BODY_lst:
        with open(name_subdir +"/SizeRestrictions_BODY", "w") as out:
            json.dump(SizeRestrictions_BODY_lst, out)
            results[SizeRestrictions_BODY] = len(SizeRestrictions_BODY_lst)
    if SizeRestrictions_URIPATH_lst:
        with open(name_subdir +"/SizeRestrictions_URIPATH", "w") as out:
            json.dump(SizeRestrictions_URIPATH_lst, out)
            results[SizeRestrictions_URIPATH] = len(SizeRestrictions_URIPATH_lst)
    if EC2MetaDataSSRF_BODY_lst:
        with open(name_subdir +"/EC2MetaDataSSRF_BODY", "w") as out:
            json.dump(EC2MetaDataSSRF_BODY_lst, out)
            results[EC2MetaDataSSRF_BODY] = len(EC2MetaDataSSRF_BODY_lst)
    if EC2MetaDataSSRF_COOKIE_lst:
        with open(name_subdir +"/EC2MetaDataSSRF_COOKIE", "w") as out:
            json.dump(EC2MetaDataSSRF_COOKIE_lst, out)
            results[EC2MetaDataSSRF_COOKIE] = len(EC2MetaDataSSRF_COOKIE_lst)
    if EC2MetaDataSSRF_QUERYARGUMENTS_lst:
        with open(name_subdir +"/EC2MetaDataSSRF_QUERYARGUMENTS", "w") as out:
            json.dump(EC2MetaDataSSRF_QUERYARGUMENTS_lst, out)
            results[EC2MetaDataSSRF_QUERYARGUMENTS] = len(EC2MetaDataSSRF_QUERYARGUMENTS_lst)
    if EC2MetaDataSSRF_URIPATH_lst:
        with open(name_subdir +"/EC2MetaDataSSRF_URIPATH", "w") as out:
            json.dump(EC2MetaDataSSRF_URIPATH_lst, out)
            results[EC2MetaDataSSRF_URIPATH] = len(EC2MetaDataSSRF_URIPATH_lst)
    if GenericLFI_BODY_lst:
        with open(name_subdir +"/GenericLFI_BODY", "w") as out:
            json.dump(GenericLFI_BODY_lst, out)
            results[GenericLFI_BODY] = len(GenericLFI_BODY_lst)
    if GenericLFI_QUERYARGUMENTS_lst:
        with open(name_subdir +"/GenericLFI_QUERYARGUMENTS", "w") as out:
            json.dump(GenericLFI_QUERYARGUMENTS_lst, out)
            results[GenericLFI_QUERYARGUMENTS] = len(GenericLFI_QUERYARGUMENTS_lst)
    if GenericLFI_URIPATH_lst:
        with open(name_subdir +"/GenericLFI_URIPATH", "w") as out:
            json.dump(GenericLFI_URIPATH_lst, out)
            results[GenericLFI_URIPATH] = len(GenericLFI_URIPATH_lst)
    if RestrictedExtensions_URIPATH_lst:
        with open(name_subdir +"/RestrictedExtensions_URIPATH", "w") as out:
            json.dump(RestrictedExtensions_URIPATH_lst, out)
            results[RestrictedExtensions_URIPATH] = len(RestrictedExtensions_URIPATH_lst)
    if RestrictedExtensions_QUERYARGUMENTS_lst:
        with open(name_subdir +"/RestrictedExtensions_QUERYARGUMENTS", "w") as out:
            json.dump(RestrictedExtensions_QUERYARGUMENTS_lst, out)
            results[RestrictedExtensions_QUERYARGUMENTS] = len(RestrictedExtensions_QUERYARGUMENTS_lst)
    if GenericRFI_BODY_lst:
        with open(name_subdir +"/GenericRFI_BODY", "w") as out:
            json.dump(GenericRFI_BODY_lst, out)
            results[GenericRFI_BODY] = len(GenericRFI_BODY_lst)
    if GenericRFI_QUERYARGUMENTS_lst:
        with open(name_subdir +"/GenericRFI_QUERYARGUMENTS", "w") as out:
            json.dump(GenericRFI_QUERYARGUMENTS_lst, out)
            results[GenericRFI_QUERYARGUMENTS] = len(GenericRFI_QUERYARGUMENTS_lst)
    if GenericRFI_URIPATH_lst:
        with open(name_subdir +"/GenericRFI_URIPATH", "w") as out:
            json.dump(GenericRFI_URIPATH_lst, out)
            results[GenericRFI_URIPATH] = len(GenericRFI_URIPATH_lst)
    if CrossSiteScripting_COOKIE_lst:
        with open(name_subdir +"/CrossSiteScripting_COOKIE", "w") as out:
            json.dump(CrossSiteScripting_COOKIE_lst, out)
            results[CrossSiteScripting_COOKIE] = len(CrossSiteScripting_COOKIE_lst)
    if CrossSiteScripting_URIPATH_lst:
        with open(name_subdir +"/CrossSiteScripting_URIPATH", "w") as out:
            json.dump(CrossSiteScripting_URIPATH_lst, out)
            results[CrossSiteScripting_URIPATH] = len(CrossSiteScripting_URIPATH_lst)
    if CrossSiteScripting_QUERYARGUMENTS_lst:
        with open(name_subdir +"/CrossSiteScripting_QUERYARGUMENTS", "w") as out:
            json.dump(CrossSiteScripting_QUERYARGUMENTS_lst, out)
            results[CrossSiteScripting_QUERYARGUMENTS] = len(CrossSiteScripting_QUERYARGUMENTS_lst)
    if CrossSiteScripting_BODY_lst:
        with open(name_subdir +"/CrossSiteScripting_BODY", "w") as out:
            json.dump(CrossSiteScripting_BODY_lst, out)
            results[CrossSiteScripting_BODY] = len(CrossSiteScripting_BODY_lst)
    if Default_Action_lst:
        with open(name_subdir +"/Default_Action", "w") as out:
            json.dump(Default_Action_lst, out)
            results[Default_Action] = len(Default_Action_lst)
    if Block_CN_Rule_lst:
        with open(name_subdir +"/Block_CN_Rule", "w") as out:
            json.dump(Block_CN_Rule_lst, out)
            results[Block_CN_Rule] = len(Block_CN_Rule_lst)

for input_file in os.scandir("."):
    if (input_file.is_file() and not input_file.path.endswith(".py")):
        with open(input_file.name,"r") as file:
            line_counter = 0
            for line in file:
                line_counter += 1
                log = json.loads(line)
                if len(log['ruleGroupList']) == 0:
                    continue
                terminatingRule = log['ruleGroupList'][0]
                if not isinstance(terminatingRule['terminatingRule'], None.__class__) :
                    terminatingRule = terminatingRule['terminatingRule']['ruleId']
                else:
                    appendLog(Default_Action, log)
                    continue
                appendLog(terminatingRule, log)

        results["Total"] = line_counter
        name_subdir = "results" + input_file.name 
        os.mkdir(name_subdir)
        
        writeToRuleFile(name_subdir)
        with open(name_subdir +"/Results.txt", "w") as res:
            json.dump(results, res, indent=4)
        print(results)
