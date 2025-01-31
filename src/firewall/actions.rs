use anyhow::anyhow;
use serde::Serialize;
use std::str::FromStr;

// FIXME: action notrack for raw chains

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Action {
    Accept,
    Drop,
    Log,
    Return,
    AddDstToAddressList,
    FastTrackConnection,
    Passthrough,
    Tarpit,
    AddSrcToAddressList,
    Jump,
    Reject,
    // TODO: don't allow these actions to be used in every chain ?
    // mangle table actions
    MarkConnection,
    MarkPacket,
    // raw table actions
    NoTrack,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match &self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Log => "log",
            Action::Return => "return",
            Action::AddDstToAddressList => "add-dst-to-address-list",
            Action::FastTrackConnection => "fasttrack-connection",
            Action::Passthrough => "passthrough",
            Action::Tarpit => "tarpit",
            Action::AddSrcToAddressList => "add-src-to-address-list",
            Action::Jump => "jump",
            Action::Reject => "reject",
            Action::MarkConnection => "mark-connection",
            Action::MarkPacket => "mark-packet",
            Action::NoTrack => "no-track",
        }
    }
}

impl FromStr for Action {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "accept" => Ok(Action::Accept),
            "drop" => Ok(Action::Drop),
            "log" => Ok(Action::Log),
            "return" => Ok(Action::Return),
            "add-dst-to-address-list" => Ok(Action::AddDstToAddressList),
            "fasttrack-connection" => Ok(Action::FastTrackConnection),
            "passthrough" => Ok(Action::Passthrough),
            "tarpit" => Ok(Action::Tarpit),
            "add-src-to-address-list" => Ok(Action::AddSrcToAddressList),
            "jump" => Ok(Action::Jump),
            "reject" => Ok(Action::Reject),
            "mark-connection" => Ok(Action::MarkConnection),
            "mark-packet" => Ok(Action::MarkPacket),
            "no-track" => Ok(Action::NoTrack),
            _ => Err(anyhow!("unexpected action: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {

    use assert2::check;

    use super::Action;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case("accept", Some(Action::Accept))]
    #[case("drop", Some(Action::Drop))]
    #[case("log", Some(Action::Log))]
    #[case("return", Some(Action::Return))]
    #[case("add-dst-to-address-list", Some(Action::AddDstToAddressList))]
    #[case("fasttrack-connection", Some(Action::FastTrackConnection))]
    #[case("passthrough", Some(Action::Passthrough))]
    #[case("tarpit", Some(Action::Tarpit))]
    #[case("add-src-to-address-list", Some(Action::AddSrcToAddressList))]
    #[case("jump", Some(Action::Jump))]
    #[case("reject", Some(Action::Reject))]
    #[case("mark-connection", Some(Action::MarkConnection))]
    #[case("mark-packet", Some(Action::MarkPacket))]
    #[case("no-track", Some(Action::NoTrack))]
    #[case("unknown", None)]
    fn test_action(#[case] name: &str, #[case] value: Option<Action>) {
        if value.is_some() {
            let v = value.unwrap();
            check!(Action::from_str(name).unwrap() == v);
            check!(v.as_str() == name);
        } else {
            // an error case
            check!(Action::from_str(name).is_err());
        }
    }
}
