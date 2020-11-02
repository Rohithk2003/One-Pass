from geopy.geocoders import Nominatim
import geocoder
geolocator = Nominatim(user_agent="geoapiExercises")
def city_state_country(coord):
    location = geolocator.reverse(coord, exactly_one=True)
    address = location.raw['address']
    city = address.get('city', '')
    state = address.get('state', '')
    country = address.get('country', '')
    return city, state, country
g = geocoder.ip('me')
a = g.latlng
print(a)
print(city_state_country(a))
