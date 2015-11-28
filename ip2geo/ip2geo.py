#!/usr/bin/python

# -*- coding: utf-8 -*-
import geoip2.database

r = geoip2.database.Reader('./GeoLite2-City.mmdb')

res = r.city(raw_input('Enter IP address : '))
print 'country name : ', res.country.name
print 'country code : ', res.country.iso_code
print 'state name?  : ', res.subdivisions.most_specific.name
print 'city name    : ', res.city.name
print 'latitude     : ', res.location.latitude
print 'longitude    : ', res.location.longitude

