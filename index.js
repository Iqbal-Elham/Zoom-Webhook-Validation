require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 4000;

app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.status(200);
  res.send(
    `Zoom Webhook Validation successfully running. Set this URL with the /webhook path as your apps Event notification endpoint URL. https://github.com/Iqbal-Elham/Zoom-Webhook-Validation`
  );
});

app.post("/webhook", (req, res) => {
  var response;

  console.log(req.headers);
  console.log(req.body);

  // construct the message string
  const message = `v0:${req.headers["x-zm-request-timestamp"]}:${JSON.stringify(
    req.body
  )}`;

  const hashForVerify = crypto
    .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
    .update(message)
    .digest("hex");

  // hash the message string with your Webhook Secret Token and prepend the version semantic
  const signature = `v0=${hashForVerify}`;

  // you validating the request came from Zoom https://marketplace.zoom.us/docs/api-reference/webhook-reference#notification-structure
  if (req.headers["x-zm-signature"] === signature) {
    // Zoom validating you control the webhook endpoint https://marketplace.zoom.us/docs/api-reference/webhook-reference#validate-webhook-endpoint
    if (req.body.event === "endpoint.url_validation") {
      const hashForValidate = crypto
        .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
        .update(req.body.payload.plainToken)
        .digest("hex");

      response = {
        message: {
          plainToken: req.body.payload.plainToken,
          encryptedToken: hashForValidate,
        },
        status: 200,
      };

      console.log(response.message);

      res.status(response.status);
      res.json(response.message);
    } else {
      response = {
        message: "Authorized request to Zoom Webhook sample.",
        status: 200,
      };
      // Make a POST request with a JSON payload.

      const formData = { body: req.body.payload.object.id };
      const fetchData = async () => {
        try {
          const response = await axios.post(
            `https://www.zohoapis.com/crm/v2/functions/testzoom1/actions/execute?auth_type=apikey&zapikey=1003.41aadb9c21f6df93dafb0c76c0d317f1.2033e8d19d458c246aa8c0f07a691876`,
            JSON.stringify(formData)
          );

          const contentText = response.data;
          console.log("contentText: " + contentText);
        } catch (error) {
          console.log("Error is " + error);
        }
      };

      fetchData();
    }
  } else {
    response = {
      message: "Unauthorized request to Zoom Webhook sample.",
      status: 401,
    };

    console.log(response.message);

    res.status(response.status);
    res.json(response);
  }
});

app.listen(port, () =>
  console.log(`Zoom Webhook sample listening on port ${port}!`)
);
