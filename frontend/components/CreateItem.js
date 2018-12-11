import React, { Component } from 'react'
import Router from 'next/router'
import { Mutation } from 'react-apollo'
import gql from 'graphql-tag'
import Form from './styles/Form'
import Error from './ErrorMessage'
import formatMoney from '../lib/formatMoney'

const CREATE_ITEM_MUTATION = gql`
  mutation CREATE_ITEM_MUTATION(
    $title: String!
    $description: String!
    $price: Int!
    $image: String
    $largeImage: String
  ) {
    createItem(
      title: $title
      description: $description
      price: $price
      image: $image
      largeImage: $largeImage
    ) {
      id
    }
  }
`

class CreateItem extends Component {
  state = {
    title: 'Cool Shoes',
    description: 'Some description',
    image: 'myimage.jpg',
    largeImage: 'bigimage.jpg',
    price: 1000,
  }

  handleChange = (e) => {
    const { name, type, value } = e.target
    const val = type === 'number' ? parseFloat(value) : value
    this.setState({ [name]: val })
  }

  uploadFile = async e => {
    console.log('Uploading File')
    const files = e.target.files
    const data = new FormData()
    data.append('file', files[0])
    data.append('upload_preset', 'sickfits')

    const res = await fetch('https://api.cloudinary.com/v1_1/dco1869kt/image/upload', {
      method: 'POST',
      body: data,
    })
    const file = await res.json()
    console.log(file)
    this.setState({
      image: file.secure_url,
      largeImage: file.eager[0].secure_url
    })
  }

  render() {
    return (
      <Mutation mutation={CREATE_ITEM_MUTATION} variables={this.state}>
        {(createItem, { loading, error }) => (

          <Form onSubmit={async e => {
            // stop the form from submitting
            e.preventDefault()
            //
            console.log(this.state)
            const res = await createItem()
            console.log(res)
            Router.push({
              pathname: '/item',
              query: { id: res.data.createItem.id }
            })
          }}>
            <Error error={error} />
            <fieldset disabled={loading} aria-busy={loading}>
              <label htmlFor="file">
                File
            <input type="file" id="file" name="file" placeholder="Upload an image" required onChange={this.uploadFile} />
                {this.state.image && (<img src={this.state.image} alt="Upload Preview" />)}
              </label>
              <label htmlFor="title">
                Title
            <input type="text" id="title" name="title" placeholder="title" required value={this.state.title} onChange={this.handleChange} />
              </label>
              <label htmlFor="price">
                Price
            <input type="text" id="price" name="price" placeholder="price" required value={this.state.price} onChange={this.handleChange} />
              </label>
              <label htmlFor="description">
                Description
            <input type="text" id="description" name="description" placeholder="Enter A Description" required value={this.state.description} onChange={this.handleChange} />
              </label>
              <button type="submit">Submit</button>
            </fieldset>
          </Form>
        )}
      </Mutation>
    )
  }
}

export default CreateItem
export { CREATE_ITEM_MUTATION }
