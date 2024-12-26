import json
from asgiref.sync import async_to_sync
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from channels.db import database_sync_to_async
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import urllib.parse

class ChatConsumer(AsyncWebsocketConsumer):
    """
    Websocket endpoint where new connections are established, awaiting messages and responses are made.
    Connections requests are made from javascript.

    Methods:
        connect : Handles new connections. User requesting new connections are authenticated using token.
        disconnect : Handles closing request for an existing connection.
        receive : Awaits for any new messages in active channels. When received, required actions are performed and message is forwarded active endpoints in same group.
        send_message_to_frontend : Handles sending messages generated from backend to frontend.
        chat_message : Handles calling consumer function which send message from backend to frontend.
    """

    @method_decorator(csrf_exempt)
    async def connect(self):
        """
        This function is called first when new connections/channels are to be created.
        Before creating new channels, user must be authenticated. User token is validated make sure the user is logged in.

        Args:
            default arguments (Request): The HTTP request object containing query parameters.

        Returns:
            Response: Success if connection created, failure message if connection failed (handled by default channels functions).
        """
        User = get_user_model()

        # Get the query string from scope and decode it
        query_string = self.scope['query_string'].decode('utf-8')
        
        # Parse the query string into a dictionary
        query_params = urllib.parse.parse_qs(query_string)
        
        # Extract the token from the query parameters (list of values)
        auth_token = query_params.get('token', [None])[0]

        if not auth_token:
            await self.close()  # Close the connection if the token is not present
            return

        try:
            from rest_framework_simplejwt.tokens import AccessToken
            # Validate the token using SimpleJWT's AccessToken
            validated_token = AccessToken(auth_token)
            
            # Retrieve user ID from the token
            user_id = validated_token['user_id']

            # Since we're in an async context, use database_sync_to_async for DB operations
            user = await database_sync_to_async(User.objects.get)(id=user_id)

            # If the user is successfully authenticated, proceed to accept the connection
            if user:
                self.room_name = self.scope['url_route']['kwargs']['room_name']
                self.room_group_name = f"chat_{self.room_name}"

                # Join room group
                await self.channel_layer.group_add(self.room_group_name, self.channel_name)
                await self.accept()
            else:
                await self.close()

        except (KeyError, IndexError, User.DoesNotExist) as e:
            # Catch missing token, invalid token structure, or user not found
            await self.close()
    
    async def disconnect(self, code):
        """
        This function handles connections/channels termibnation process.

        Args:
            default arguments (Request): The HTTP request object containing query parameters.

        Returns:
            Response: A message stating connection closed and termination status
        """
        # leave room group
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
    
    async def receive(self, text_data=None, bytes_data=None):
        """
        Awaits for any new messages in active channels. When received, required actions are performed and message is forwarded active endpoints in same group.

        Args:
            default arguments (Request): The HTTP request object containing query parameters.
            text_data (string): Message body in text format.
            bytes_data (string): Message body in byte format.

        Returns:
            Response: Message body and type of socket message.
        """
        text_data_json = json.loads(text_data)
        message = text_data_json['data']

        # send message to room group
        await self.channel_layer.group_send(self.room_group_name, {"type": "chat.message", "data": message})

    async def send_message_to_frontend(self, message):
        """
        Handles sending messages generated from backend to frontend.

        Args:
            default arguments (Request): The HTTP request object.
            message (string): Message body list containing message content and type.

        Returns:
            Response: True (Boolean, default).
        """
        await self.send(text_data=json.dumps({
            'data': message
        }))
    
    async def chat_message(self, event):
        """
        Handles calling consumer function which send message from backend to frontend.
        This function invokes consumer 'send_message_to_frontend' function to send message to active channel/connections.

        Args:
            default arguments (Request): The HTTP request object.
            event : Contains message body list having message content and type.

        Returns:
            Response: True (Boolean, default).
        """
        message = event['data']
        # send message to websocket
        await self.send(text_data=json.dumps({"data":message}))
