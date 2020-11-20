---
title: Rotate Source IPs (Part 1) - AWS API Gateway
author: bigb0ss
date: 2020-11-19 23:36:00 +0800
categories: [RedTeam, Infrastructure, Cloud, AWS]
tags: [aws api gateway, cloud, rotate ip, redteam]
image: /assets/img/post/redteam/infra/cloud/aws/logo.png
---

# Intro

During a security engagement, especially for an evasive/covert type of assessment, you might need to hide your traffic as much as possible. Or the client has implemented some type of IP based blocking, you might need to rotate your source IPs to bypass it to do something like password spraying, web application enumeration, etc. Also, Microsfot is no longer considering user enumeration as their "feature". So, if you are trying to do a password guessing/user-enumeration against one of their Office365 APIs like ActiveSync or rst2.srf (SOAP API), Microsoft has implemented a defense that after a numer of queries, it will start to throw error code saying the user account is locked out whehter it is valid or invalid. To bypass this, rotating your source IPs is required. In this blog post, I will show how to use AWS API Gateway to rotate source IPs to access a target URL. 

# AWS API Gateway Setup

Login to your AWS account 
  --> Click `Services` drop-down menu 
  --> Select `API Gateway` under the "Networking & Content Delivery"

![image](/assets/img/post/redteam/infra/cloud/aws/01.png)

Select `REST API` 

>**NOTE**: This will allow synchronous communication.

![image](/assets/img/post/redteam/infra/cloud/aws/02.png)

