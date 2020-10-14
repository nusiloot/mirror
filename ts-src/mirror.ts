function reflect() {
  const urlHref = document.location.href;
  const title = document.title;
  const reflectedParams = findReflection();
  if (reflectedParams.length > 0) {
    let mirrorData = <MirrorData>{
      url: urlHref,
      parameters: reflectedParams,
      title: title,
    };
    addToMirror(mirrorData);
  }
}

function findReflection() {
  const hashUrl = document.location.hash.replace("#", "");
  const searchUrl = document.location.search.replace("?", "");
  const hashParams = getParams(hashUrl);
  const searchParams = getParams(searchUrl);
  const rawParams = hashParams.concat(searchParams);
  const decodedParams = rawParams.map((param) => decodeURIComponent(param));
  const allParams = rawParams.concat(decodedParams);
  const uniqueParams = Array.from(new Set(allParams));
  const body = document.body.innerHTML;
  const reflectedParams = uniqueParams.filter((param) => body.includes(param));
  return reflectedParams;
}

function getParams(params: string): string[] {
  const keyValues = params
    .split("&")
    .map((param) => {
      const kv = param.split("=");
      if (kv.length == 2) {
        return kv[1];
      } else {
        return kv[0];
      }
    })
    .filter((param) => param.length > 3);

  return keyValues;
}

async function addToMirror(mirroData: MirrorData) {
  fetch(`http://localhost:3033/mirror/add`, {
    method: "POST",
    mode: "cors",
    credentials: "omit",
    body: JSON.stringify(mirroData),
    headers: {
      "Content-Type": "application/json",
    },
  });
}

interface MirrorData {
  url: string;
  parameters: string[];
  title: string;
}

reflect();
