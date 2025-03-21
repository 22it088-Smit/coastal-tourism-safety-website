let latitude;
let longitude;
let place;

window.onload = async () => {

  await setTimeout(async () => {
    console.log("Loaded");
    if (document.querySelector('.lat') == null) {

      //? TO find Users current Location
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
          function (position) {
            latitude = position.coords.latitude;
            longitude
              = position.coords.longitude;
            console.log("Latitude:", latitude);
            console.log("Longitude:", longitude);

          },
          function (error) {
            console.error("Error getting geolocation:", error);
          }
        );
      } else {
        console.error("Geolocation is not supported by this browser.");
      }
    } else {
      latitude = parseFloat(document.querySelector('.lat').textContent);
      longitude = parseFloat(document.querySelector('.lon').textContent);
      place = document.querySelector('.place').textContent;
    }



    console.log(latitude, longitude);

    const options = {
      // Required: API key
     // key: 'c6pv4EGLWysonNJqKh5a3pbBlpxS2Zh1', // REPLACE WITH YOUR KEY !!!
      key: 'NQIB6RQppNvZ664pdayrprldV4ieh7Zt',
      // Put additional console output
      verbose: true,
      // particlesAnim: 'off',

      // Optional: Initial state of the map
      lat: latitude,
      lon: longitude,
      zoom: 50,
      maxZoom: 1000
    };

    await windyInit(options, windyAPI => {
      const { map, picker, utils, broadcast, store } = windyAPI;
      // All the params are stored in windyAPI.store

      addMarker(latitude, longitude, map)
      addCircle(latitude, longitude, 'green', 'cyan', 5000, map)

      picker.on('pickerOpened', ({ lat, lon, values, overlay }) => {
        // -> 48.4, 14.3, [ U,V, ], 'wind'
        console.log('opened', lat, lon, values, overlay);

        const windObject = utils.wind2obj(values);
        console.log(windObject);
      });

      picker.on('pickerClosed', () => {
        // picker was closed
        console.log("Picker CLosed");
      });

      store.on('pickerLocation', ({ lat, lon }) => {
        console.log(lat, lon);

        const { values, overlay } = picker.getParams();
        console.log('location changed', lat, lon, values, overlay);

        latitude = lat;
        longitude = lon;
      });

      // Wait since wather is rendered
      broadcast.once('redrawFinished', () => {
        // Opening of a picker (async)
        console.log("Redraw Finished");
        picker.open({ lat: latitude, lon: longitude });
        addCircle(latitude, longitude, 'red', 'cyan', 5000, map)
      });

      const levels = store.getAllowed('availLevels');
      console.log(store.get('availLevels'));
      // levels = ['surface', '850h', ... ]
      // Getting all available values for given key

      let i = 0;
      setInterval(() => {
        i = i === levels.length - 1 ? 0 : i + 1;

        // Changing Windy params at runtime
        store.set('level', levels[i]);
      }, 500);

      // Observing change of .store value
      store.on('level', level => {
        console.log(`Level was changed: ${level}`);
      });
    });
  }, 1000);

}

function addMarker(lat, lon, map) {
  console.log("Marker");
  var marker = L.marker([lat, lon]).addTo(map);
}

function addCircle(lat, lon, color, fill, rad, map) {
  console.log("Circle");
  var circle = L.circle([lat, lon], {
    color: color,
    fillColor: fill,
    fillOpacity: 0.5,
    radius: rad
  }).addTo(map);
}

// AQI COlor coding 

let aqi = parseInt(document.querySelector(".aqi h3").textContent);
let aqibox = document.querySelector(".data.aqi");

if (aqi <= 50) { aqibox.style.border = "5px solid green"; }
else if (aqi <= 100) { aqibox.style.border = "5px solid yellow"; }
else if (aqi <= 150) { aqibox.style.border = "5px solid orange"; console.log("danger hu mei"); }
else if (aqi <= 500) { aqibox.style.border = "5px solid Red"; console.log("Yanna"); }
else if (aqi <= 300) { aqibox.style.border = "5px solid Maroon"; }
else { document.querySelector(".data.aqi").style.border = "5px solid Brown"; }


//! Final Alert Color According to wave height

let waveHeight = parseFloat(document.querySelector(".data .wave h4 span").textContent);
let alertBox = document.querySelector(".alert");

let alert = document.querySelector(".alert h3")
console.log(alert.textContent);

if (waveHeight >= 0.0 && waveHeight <= 0.3) {
  alert.textContent = "Ideal to Visit";
  alertBox.style.background = "#007759"
} else if (waveHeight > 0.3 && waveHeight <= 0.5) {
  alert.textContent = "Safe to Visit";
  alertBox.style.background = "green"
} else if (waveHeight > 0.5 && waveHeight <= 1.2) {
  alert.textContent = "Be Caution";
  alertBox.style.background = "Yellow"
} else if (waveHeight > 1.2 && waveHeight <= 2.0) {
  alert.textContent = "Not reccommended";
  alertBox.style.background = "Orange"
} else if (waveHeight > 2.0 && waveHeight <= 3.0) {
  alert.textContent = "Very Dangerous";
  alertBox.style.background = "Red"
} else if (waveHeight > 3.0) {
  alert.textContent = "Hazardous";
  alertBox.style.background = "maroon"
} else {
  alert.textContent = "Invalid: Check input";
}



