package burp

import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CORS
import io.ktor.features.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.resources
import io.ktor.http.content.static
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.serialization.json
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.stop
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import java.util.concurrent.TimeUnit

class Server {
    var callbacks: IBurpExtenderCallbacks? = null
    var tab: MirrorTab? = null
    private var server: NettyApplicationEngine? = null

    private fun initServer() {
        server = embeddedServer(Netty, host = "localhost", port = 3033) {
            install(CORS) {
                anyHost()
                header("content-type")
            }

            install(ContentNegotiation) {
                json()
            }

            routing {
                get("/") {
                    call.respondText("Mirror", ContentType.Text.Html)
                }

                post("mirror/add") {
                    call.respond(HttpStatusCode.OK, "Mirror: OK")
                    val addMirror = call.receive<AddMirror>()
                    processAddRequest(addMirror)
                }

                static("/mirror") {
                    resources("static")
                }
            }
        }
    }

    private fun processAddRequest(addMirror: AddMirror) {
        callbacks?.let { cb ->
            val urlNoHash = addMirror.url.split("#").first()
            ServerUtils.findRequest(urlNoHash, cb)?.let { requestResponse ->
                val mirrorItem =
                    MirrorUtils.makeMirrorRequest(
                        addMirror.parameters,
                        requestResponse,
                        "Server",
                        addMirror.title,
                        cb,
                        addMirror.url
                    )
                tab?.mirrorPanel?.addMirrorItem(mirrorItem)
            }
        }
    }

    fun start() {
        GlobalScope.launch(Dispatchers.IO) {
            if (server == null) {
                initServer()
                server?.start(false)
            }
        }
    }

    fun stop() {
        GlobalScope.launch(Dispatchers.IO) {
            server?.stop(1, 1, TimeUnit.SECONDS)
            server = null
        }
    }
}

@Serializable
data class AddMirror(
    val url: String,
    val parameters: List<String>,
    val title: String
)
