#![allow(unused)]

use std::collections::HashMap;

use actix_web::web;
use sqlx::{Pool, Postgres};

bitflags::bitflags! {
    /// A set of permissions that can be assigned to [`User`]s and [`Role`]s via
    /// [`PermissionOverwrite`]s, roles globally in a [`Guild`], and to
    /// [`GuildChannel`]s.
    ///
    /// [`Guild`]: super::guild::Guild
    /// [`GuildChannel`]: super::channel::GuildChannel
    /// [`PermissionOverwrite`]: super::channel::PermissionOverwrite
    /// [`Role`]: super::guild::Role
    /// [`User`]: super::user::User
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permissions: i64 {
        /// Allows for the creation of [`RichInvite`]s.
        ///
        /// [`RichInvite`]: super::invite::RichInvite
        const CREATE_INSTANT_INVITE = 1 << 0;
        /// Allows for the kicking of guild [member]s.
        ///
        /// [member]: super::guild::Member
        const KICK_MEMBERS = 1 << 1;
        /// Allows the banning of guild [member]s.
        ///
        /// [member]: super::guild::Member
        const BAN_MEMBERS = 1 << 2;
        /// Allows all permissions, bypassing channel [permission overwrite]s.
        ///
        /// [permission overwrite]: super::channel::PermissionOverwrite
        const ADMINISTRATOR = 1 << 3;
        /// Allows management and editing of guild [channel]s.
        ///
        /// [channel]: super::channel::GuildChannel
        const MANAGE_CHANNELS = 1 << 4;
        /// Allows management and editing of the [guild].
        ///
        /// [guild]: super::guild::Guild
        const MANAGE_GUILD = 1 << 5;
        /// [`Member`]s with this permission can add new [`Reaction`]s to a
        /// [`Message`]. Members can still react using reactions already added
        /// to messages without this permission.
        ///
        /// [`Member`]: super::guild::Member
        /// [`Message`]: super::channel::Message
        /// [`Reaction`]: super::channel::Reaction
        const ADD_REACTIONS = 1 << 6;
        /// Allows viewing a guild's audit logs.
        const VIEW_AUDIT_LOG = 1 << 7;
        /// Allows the use of priority speaking in voice channels.
        const PRIORITY_SPEAKER = 1 << 8;
        // Allows the user to go live.
        const STREAM = 1 << 9;
        /// Allows guild members to view a channel, which includes reading
        /// messages in text channels and joining voice channels.
        const VIEW_CHANNEL = 1 << 10;
        /// Allows sending messages in a guild channel.
        const SEND_MESSAGES = 1 << 11;
        /// Allows the sending of text-to-speech messages in a channel.
        const SEND_TTS_MESSAGES = 1 << 12;
        /// Allows the deleting of other messages in a guild channel.
        ///
        /// **Note**: This does not allow the editing of other messages.
        const MANAGE_MESSAGES = 1 << 13;
        /// Allows links from this user - or users of this role - to be
        /// embedded, with potential data such as a thumbnail, description, and
        /// page name.
        const EMBED_LINKS = 1 << 14;
        /// Allows uploading of files.
        const ATTACH_FILES = 1 << 15;
        /// Allows the reading of a channel's message history.
        const READ_MESSAGE_HISTORY = 1 << 16;
        /// Allows the usage of the `@everyone` mention, which will notify all
        /// users in a channel. The `@here` mention will also be available, and
        /// can be used to mention all non-offline users.
        ///
        /// **Note**: You probably want this to be disabled for most roles and
        /// users.
        const MENTION_EVERYONE = 1 << 17;
        /// Allows the usage of custom emojis from other guilds.
        ///
        /// This does not dictate whether custom emojis in this guild can be
        /// used in other guilds.
        const USE_EXTERNAL_EMOJIS = 1 << 18;
        /// Allows for viewing guild insights.
        const VIEW_GUILD_INSIGHTS = 1 << 19;
        /// Allows the joining of a voice channel.
        const CONNECT = 1 << 20;
        /// Allows the user to speak in a voice channel.
        const SPEAK = 1 << 21;
        /// Allows the muting of members in a voice channel.
        const MUTE_MEMBERS = 1 << 22;
        /// Allows the deafening of members in a voice channel.
        const DEAFEN_MEMBERS = 1 << 23;
        /// Allows the moving of members from one voice channel to another.
        const MOVE_MEMBERS = 1 << 24;
        /// Allows the usage of voice-activity-detection in a [voice] channel.
        ///
        /// If this is disabled, then [`Member`]s must use push-to-talk.
        ///
        /// [`Member`]: super::guild::Member
        /// [voice]: super::channel::ChannelType::Voice
        const USE_VAD = 1 << 25;
        /// Allows members to change their own nickname in the guild.
        const CHANGE_NICKNAME = 1 << 26;
        /// Allows members to change other members' nicknames.
        const MANAGE_NICKNAMES = 1 << 27;
        /// Allows management and editing of roles below their own.
        const MANAGE_ROLES = 1 << 28;
        /// Allows management of webhooks.
        const MANAGE_WEBHOOKS = 1 << 29;
        /// Allows management of emojis and stickers created without the use of an
        /// [`Integration`].
        ///
        /// [`Integration`]: super::guild::Integration
        const MANAGE_EMOJIS_AND_STICKERS = 1 << 30;
        /// Allows using slash commands.
        const USE_SLASH_COMMANDS = 1 << 31;
        /// Allows for requesting to speak in stage channels.
        const REQUEST_TO_SPEAK = 1 << 32;
        /// Allows for creating, editing, and deleting scheduled events
        const MANAGE_EVENTS = 1 << 33;
        /// Allows for deleting and archiving threads, and viewing all private threads.
        const MANAGE_THREADS = 1 << 34;
        /// Allows for creating threads.
        const CREATE_PUBLIC_THREADS = 1 << 35;
        /// Allows for creating private threads.
        const CREATE_PRIVATE_THREADS = 1 << 36;
        /// Allows the usage of custom stickers from other servers.
        const USE_EXTERNAL_STICKERS = 1 << 37;
        /// Allows for sending messages in threads
        const SEND_MESSAGES_IN_THREADS = 1 << 38;
        /// Allows for launching activities in a voice channel
        const USE_EMBEDDED_ACTIVITIES = 1 << 39;
        /// Allows for timing out users to prevent them from sending or reacting to messages in
        /// chat and threads, and from speaking in voice and stage channels.
        const MODERATE_MEMBERS = 1 << 40;
    }
}

pub struct PERM {}

impl PERM {
    /// Allows for the creation of [`RichInvite`]s.
    ///
    /// [`RichInvite`]: super::invite::RichInvite
    pub const CREATE_INSTANT_INVITE: i64 = 1 << 0;
    /// Allows for the kicking of guild [member]s.
    ///
    /// [member]: super::guild::Member
    pub const KICK_MEMBERS: i64 = 1 << 1;
    /// Allows the banning of guild [member]s.
    ///
    /// [member]: super::guild::Member
    pub const BAN_MEMBERS: i64 = 1 << 2;
    /// Allows all permissions, bypassing channel [permission overwrite]s.
    ///
    /// [permission overwrite]: super::channel::PermissionOverwrite
    pub const ADMINISTRATOR: i64 = 1 << 3;
    /// Allows management and editing of guild [channel]s.
    ///
    /// [channel]: super::channel::GuildChannel
    pub const MANAGE_CHANNELS: i64 = 1 << 4;
    /// Allows management and editing of the [guild].
    ///
    /// [guild]: super::guild::Guild
    pub const MANAGE_GUILD: i64 = 1 << 5;
    /// [`Member`]s with this permission can add new [`Reaction`]s to a
    /// [`Message`]. Members can still react using reactions already added
    /// to messages without this permission.
    ///
    /// [`Member`]: super::guild::Member
    /// [`Message`]: super::channel::Message
    /// [`Reaction`]: super::channel::Reaction
    pub const ADD_REACTIONS: i64 = 1 << 6;
    /// Allows viewing a guild's audit logs.
    pub const VIEW_AUDIT_LOG: i64 = 1 << 7;
    /// Allows the use of priority speaking in voice channels.
    pub const PRIORITY_SPEAKER: i64 = 1 << 8;
    // Allows the user to go live.
    pub const STREAM: i64 = 1 << 9;
    /// Allows guild members to view a channel, which includes reading
    /// messages in text channels and joining voice channels.
    pub const VIEW_CHANNEL: i64 = 1 << 10;
    /// Allows sending messages in a guild channel.
    pub const SEND_MESSAGES: i64 = 1 << 11;
    /// Allows the sending of text-to-speech messages in a channel.
    pub const SEND_TTS_MESSAGES: i64 = 1 << 12;
    /// Allows the deleting of other messages in a guild channel.
    ///
    /// **Note**: This does not allow the editing of other messages.
    pub const MANAGE_MESSAGES: i64 = 1 << 13;
    /// Allows links from this user - or users of this role - to be
    /// embedded, with potential data such as a thumbnail, description, and
    /// page name.
    pub const EMBED_LINKS: i64 = 1 << 14;
    /// Allows uploading of files.
    pub const ATTACH_FILES: i64 = 1 << 15;
    /// Allows the reading of a channel's message history.
    pub const READ_MESSAGE_HISTORY: i64 = 1 << 16;
    /// Allows the usage of the `@everyone` mention, which will notify all
    /// users in a channel. The `@here` mention will also be available, and
    /// can be used to mention all non-offline users.
    ///
    /// **Note**: You probably want this to be disabled for most roles and
    /// users.
    pub const MENTION_EVERYONE: i64 = 1 << 17;
    /// Allows the usage of custom emojis from other guilds.
    ///
    /// This does not dictate whether custom emojis in this guild can be
    /// used in other guilds.
    pub const USE_EXTERNAL_EMOJIS: i64 = 1 << 18;
    /// Allows for viewing guild insights.
    pub const VIEW_GUILD_INSIGHTS: i64 = 1 << 19;
    /// Allows the joining of a voice channel.
    pub const CONNECT: i64 = 1 << 20;
    /// Allows the user to speak in a voice channel.
    pub const SPEAK: i64 = 1 << 21;
    /// Allows the muting of members in a voice channel.
    pub const MUTE_MEMBERS: i64 = 1 << 22;
    /// Allows the deafening of members in a voice channel.
    pub const DEAFEN_MEMBERS: i64 = 1 << 23;
    /// Allows the moving of members from one voice channel to another.
    pub const MOVE_MEMBERS: i64 = 1 << 24;
    /// Allows the usage of voice-activity-detection in a [voice] channel.
    ///
    /// If this is disabled, then [`Member`]s must use push-to-talk.
    ///
    /// [`Member`]: super::guild::Member
    /// [voice]: super::channel::ChannelType::Voice
    pub const USE_VAD: i64 = 1 << 25;
    /// Allows members to change their own nickname in the guild.
    pub const CHANGE_NICKNAME: i64 = 1 << 26;
    /// Allows members to change other members' nicknames.
    pub const MANAGE_NICKNAMES: i64 = 1 << 27;
    /// Allows management and editing of roles below their own.
    pub const MANAGE_ROLES: i64 = 1 << 28;
    /// Allows management of webhooks.
    pub const MANAGE_WEBHOOKS: i64 = 1 << 29;
    /// Allows management of emojis and stickers created without the use of an
    /// [`Integration`].
    ///
    /// [`Integration`]: super::guild::Integration
    pub const MANAGE_EMOJIS_AND_STICKERS: i64 = 1 << 30;
    /// Allows using slash commands.
    pub const USE_SLASH_COMMANDS: i64 = 1 << 31;
    /// Allows for requesting to speak in stage channels.
    pub const REQUEST_TO_SPEAK: i64 = 1 << 32;
    /// Allows for creating, editing, and deleting scheduled events
    pub const MANAGE_EVENTS: i64 = 1 << 33;
    /// Allows for deleting and archiving threads, and viewing all private threads.
    pub const MANAGE_THREADS: i64 = 1 << 34;
    /// Allows for creating threads.
    pub const CREATE_PUBLIC_THREADS: i64 = 1 << 35;
    /// Allows for creating private threads.
    pub const CREATE_PRIVATE_THREADS: i64 = 1 << 36;
    /// Allows the usage of custom stickers from other servers.
    pub const USE_EXTERNAL_STICKERS: i64 = 1 << 37;
    /// Allows for sending messages in threads
    pub const SEND_MESSAGES_IN_THREADS: i64 = 1 << 38;
    /// Allows for launching activities in a voice channel
    pub const USE_EMBEDDED_ACTIVITIES: i64 = 1 << 39;
    /// Allows for timing out users to prevent them from sending or reacting to messages in
    /// chat and threads, and from speaking in voice and stage channels.
    pub const MODERATE_MEMBERS: i64 = 1 << 40;
}

pub async fn get_everyone_permission_for_guild(
    pool: &web::Data<Pool<Postgres>>,
    guild_id: i64,
) -> i64 {
    // Get @everyone role
    let res = match sqlx::query!(
        "SELECT permission FROM roles 
			WHERE guild_id =$1 AND role_id =$1",
        guild_id
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(ok) => ok,
        Err(_) => {
            panic!("Error ")
        }
    };

    res.permission
}

pub async fn get_combined_perm_for_user(
    pool: &web::Data<Pool<Postgres>>,
    guild_id: i64,
    user_id: i64,
) -> i64 {
    let res = match sqlx::query!(
        "SELECT permissions, owner FROM user_guilds 
		WHERE user_id = $1 
		AND id = $2",
        user_id,
        guild_id
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(ok) => ok,
        Err(_) => {
            // TODO:
            panic!("Error ")
        }
    };
    res.permissions
}

pub async fn perms_for_roles_for_channel(
    pool: &web::Data<Pool<Postgres>>,
    user_id: i64,
    guild_id: i64,
    perm_hash: &mut HashMap<i64, [i64; 2]>,
) {
    let perms_for_roles_for_channel = match sqlx::query!(
        "SELECT  allow as \"allow!\", deny as \"deny!\", channel_id as \"channel_id!\", role_id as 
		\"role_id!\" FROM get_roles_overwrites_for_channels_from_user($1, $2)",
        user_id,
        guild_id
    )
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(ok) => ok,
        Err(_) => {
            panic!("Error ")
        }
    };

    for perm in perms_for_roles_for_channel {
        if perm.channel_id == guild_id {
            // Dont include the generic @everyone
            continue;
        } else {
            match perm_hash.get_mut(&perm.channel_id) {
                Some(ok) => {
                    ok[0] = ok[0] | perm.allow;
                    ok[1] = ok[1] | perm.deny;
                }
                None => continue,
            }
        }
    }
}

pub async fn get_everyone_permission_for_each_channel(
    pool: &web::Data<Pool<Postgres>>,
    guild_id: i64,
    perm_hash: &mut HashMap<i64, [i64; 2]>,
) {
    let everyone_permissions = match sqlx::query!(
        "SELECT channel_permissions.allow as \"allow?\", channel_permissions.deny as \"deny?\",  channels.channel_id, channels.name 
		FROM channels 
		LEFT JOIN channel_permissions 
		ON channels.channel_id=channel_permissions.channel_id OR channel_permissions.channel_id IS NULL
		WHERE channels.type = 2
		AND channels.guild_id=$1
		AND (channel_permissions.target_id=$1 OR channel_permissions.target_id IS NULL)", guild_id
    )
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(ok) => ok,
        Err(_) => {
            panic!("Error ")
        }
	};

    for channel_perm in everyone_permissions {
        match perm_hash.get_mut(&channel_perm.channel_id) {
            Some(ok) => {
                ok[0] = ok[0] | channel_perm.allow.unwrap_or(0);
                ok[1] = ok[1] | channel_perm.deny.unwrap_or(0);
            }
            None => continue,
        }
    }
}
